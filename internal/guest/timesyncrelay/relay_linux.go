//go:build linux

// Package timesyncrelay connects the native IC stream to the sibling provider.
package timesyncrelay

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"time"
	"unsafe"

	"github.com/Microsoft/hcsshim/internal/timesync"
	"golang.org/x/sys/unix"
)

const (
	devicePath = "/dev/diode-timesync"
	infoIOCTL  = 0x80185400 // _IOR('T', 0, struct diode_timesync_info)
	infoSize   = 24
	infoOpen   = 1
	infoDead   = 2
)

type deviceInfo struct {
	Size     uint32
	Version  uint32
	Max      uint32
	Flags    uint32
	Reserved [2]uint32
}

var (
	_ [infoSize - int(unsafe.Sizeof(deviceInfo{}))]byte
	_ [int(unsafe.Sizeof(deviceInfo{})) - infoSize]byte
)

// openDevice waits for initial device creation, not for a time sample or peer.
func openDevice(ctx context.Context) (int, error) {
	for {
		fd, err := unix.Open(devicePath, unix.O_RDWR|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
		if err == nil {
			return fd, nil
		}
		if !errors.Is(err, unix.ENOENT) {
			return -1, fmt.Errorf("timesyncrelay: open device: %w", err)
		}
		timer := time.NewTimer(100 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return -1, ctx.Err()
		case <-timer.C:
		}
	}
}

// checkDevice verifies the fixed-width provider ABI before reporting readiness.
func checkDevice(fd int) error {
	var info deviceInfo
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), infoIOCTL, uintptr(unsafe.Pointer(&info)))
	if errno != 0 {
		return fmt.Errorf("timesyncrelay: get device info: %w", errno)
	}
	if info.Size != infoSize || info.Version != 1 || info.Max != timesync.MaxRecordSize ||
		info.Flags & ^uint32(infoOpen|infoDead) != 0 || info.Reserved != [2]uint32{} {
		return fmt.Errorf("timesyncrelay: incompatible device info: %+v", info)
	}
	if info.Flags&infoDead != 0 {
		return errors.New("timesyncrelay: provider already terminal")
	}
	return nil
}

// Run validates the provider, publishes readiness, and relays one bounded IC
// record at a time in each direction. All protocol I/O is on stdin/stdout;
// callers report errors on stderr. Peer loss and malformed records are fatal.
func Run(ctx context.Context, readyPath string) error {
	if readyPath == "" {
		return errors.New("timesyncrelay: readiness path is required")
	}
	fd, err := openDevice(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(fd) }()
	if err := checkDevice(fd); err != nil {
		return err
	}
	return relay(ctx, fd, int(os.Stdin.Fd()), int(os.Stdout.Fd()), readyPath)
}

// relay uses nonblocking descriptors and an eventfd so cancellation never relies
// on closing a descriptor while another thread is blocked in a device syscall.
func relay(ctx context.Context, device, input, output int, readyPath string) error {
	for _, fd := range []int{input, output} {
		if err := unix.SetNonblock(fd, true); err != nil {
			return fmt.Errorf("timesyncrelay: set nonblocking stdio: %w", err)
		}
	}
	cancelFD, err := unix.Eventfd(0, unix.EFD_CLOEXEC|unix.EFD_NONBLOCK)
	if err != nil {
		return fmt.Errorf("timesyncrelay: create cancellation event: %w", err)
	}
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		defer close(done)
		for {
			_, err := unix.Write(cancelFD, []byte{1, 0, 0, 0, 0, 0, 0, 0})
			if !errors.Is(err, unix.EINTR) {
				break
			}
		}
	})
	defer func() {
		if !stop() {
			<-done
		}
		_ = unix.Close(cancelFD)
	}()

	if err := ctx.Err(); err != nil {
		return err
	}
	ready, err := os.OpenFile(readyPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("timesyncrelay: create readiness: %w", err)
	}
	defer func() {
		if err := os.Remove(readyPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			_, _ = fmt.Fprintf(os.Stderr, "timesyncrelay: remove readiness: %v\n", err)
		}
	}()
	if err := ready.Chmod(0600); err != nil {
		_ = ready.Close()
		return fmt.Errorf("timesyncrelay: set readiness permissions: %w", err)
	}
	if err := ready.Close(); err != nil {
		return fmt.Errorf("timesyncrelay: close readiness: %w", err)
	}

	var in, out [timesync.MaxRecordSize]byte
	inUsed, inWant, outUsed, outSent := 0, timesync.HeaderSize, 0, 0
	for {
		deviceEvents := int16(0)
		if inUsed == inWant && inWant > timesync.HeaderSize {
			deviceEvents |= unix.POLLOUT
		}
		if outUsed == 0 {
			deviceEvents |= unix.POLLIN
		}
		inputEvents, outputEvents := int16(0), int16(0)
		if inUsed < inWant {
			inputEvents = unix.POLLIN
		}
		if outUsed != 0 {
			outputEvents = unix.POLLOUT
		}
		fds := []unix.PollFd{
			{Fd: int32(cancelFD), Events: unix.POLLIN},
			{Fd: int32(device), Events: deviceEvents},
			{Fd: int32(input), Events: inputEvents},
			{Fd: int32(output), Events: outputEvents},
		}
		if _, err := unix.Poll(fds, -1); err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			return fmt.Errorf("timesyncrelay: poll: %w", err)
		}
		if fds[0].Revents != 0 || ctx.Err() != nil {
			return ctx.Err()
		}
		if fds[1].Revents&(unix.POLLERR|unix.POLLHUP|unix.POLLNVAL) != 0 {
			return errors.New("timesyncrelay: provider lost")
		}
		if inputEvents != 0 && fds[2].Revents&(unix.POLLIN|unix.POLLHUP) != 0 {
			n, err := unix.Read(input, in[inUsed:inWant])
			if err != nil && !errors.Is(err, unix.EAGAIN) && !errors.Is(err, unix.EINTR) {
				return fmt.Errorf("timesyncrelay: read stdin: %w", err)
			}
			if err == nil && n == 0 {
				return fmt.Errorf("timesyncrelay: stdin: %w", io.EOF)
			}
			if err == nil {
				inUsed += n
			}
			if inUsed == timesync.HeaderSize && inWant == timesync.HeaderSize {
				inWant, err = timesync.RecordSize(in[:timesync.HeaderSize])
				if err != nil {
					return err
				}
			}
			if inUsed == inWant {
				if err := timesync.Validate(in[:inUsed], timesync.Request); err != nil {
					return err
				}
			}
		}
		if fds[1].Revents&unix.POLLOUT != 0 && inUsed == inWant {
			n, err := unix.Write(device, in[:inUsed])
			if err != nil && !errors.Is(err, unix.EAGAIN) && !errors.Is(err, unix.EINTR) {
				return fmt.Errorf("timesyncrelay: write device: %w", err)
			}
			if err == nil {
				if n != inUsed {
					return errors.New("timesyncrelay: short device write")
				}
				inUsed, inWant = 0, timesync.HeaderSize
			}
		}
		if fds[1].Revents&unix.POLLIN != 0 && outUsed == 0 {
			n, err := unix.Read(device, out[:])
			if err != nil && !errors.Is(err, unix.EAGAIN) && !errors.Is(err, unix.EINTR) {
				return fmt.Errorf("timesyncrelay: read device: %w", err)
			}
			if err == nil {
				if n == 0 {
					return errors.New("timesyncrelay: provider closed")
				}
				if err := timesync.Validate(out[:n], timesync.Response); err != nil {
					return err
				}
				outUsed, outSent = n, 0
			}
		}
		if outputEvents != 0 && fds[3].Revents&unix.POLLOUT != 0 {
			n, err := unix.Write(output, out[outSent:outUsed])
			if err != nil && !errors.Is(err, unix.EAGAIN) && !errors.Is(err, unix.EINTR) {
				return fmt.Errorf("timesyncrelay: write stdout: %w", err)
			}
			if err == nil && n == 0 {
				return io.ErrShortWrite
			}
			if err == nil {
				outSent += n
			}
			if outSent == outUsed {
				outUsed, outSent = 0, 0
			}
		}
		if fds[2].Revents&(unix.POLLERR|unix.POLLNVAL) != 0 ||
			(inputEvents == 0 && fds[2].Revents&unix.POLLHUP != 0) ||
			fds[3].Revents&(unix.POLLERR|unix.POLLHUP|unix.POLLNVAL) != 0 {
			return errors.New("timesyncrelay: stdio lost")
		}
	}
}
