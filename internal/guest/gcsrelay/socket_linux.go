//go:build linux

package gcsrelay

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"
	"time"

	"github.com/linuxkit/virtsock/pkg/vsock"
	"golang.org/x/sys/unix"
)

// Nonblocking files use Go's poller: closing them wakes Accept/Read/Write
// without the vendor listener's blocked accept or uninterruptible dial.
type socket struct {
	file   *os.File
	local  *vsock.Addr
	remote *vsock.Addr
}

func socketFile() (*os.File, error) {
	fd, err := unix.Socket(unix.AF_VSOCK, unix.SOCK_STREAM|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), "gcsrelay-vsock"), nil
}

func control(file *os.File, f func(int) error) error {
	raw, err := file.SyscallConn()
	if err != nil {
		return err
	}
	var operation error
	if err = raw.Control(func(fd uintptr) { operation = f(int(fd)) }); err != nil {
		return err
	}
	return operation
}

func listenVSock(cid, port uint32) (net.Listener, error) {
	file, err := socketFile()
	if err != nil {
		return nil, err
	}
	err = control(file, func(fd int) error {
		if err := unix.Bind(fd, &unix.SockaddrVM{CID: cid, Port: port}); err != nil {
			return err
		}
		return unix.Listen(fd, unix.SOMAXCONN)
	})
	if err != nil {
		file.Close()
		return nil, err
	}
	return &socketListener{file: file, addr: &vsock.Addr{CID: cid, Port: port}}, nil
}

type socketListener struct {
	file *os.File
	addr *vsock.Addr
}

func (l *socketListener) Addr() net.Addr { return l.addr }
func (l *socketListener) Close() error {
	err := l.file.Close()
	if errors.Is(err, os.ErrClosed) {
		return nil
	}
	return err
}
func (l *socketListener) Accept() (net.Conn, error) {
	raw, err := l.file.SyscallConn()
	if err != nil {
		return nil, err
	}
	var fd int
	var addr unix.Sockaddr
	var acceptErr error
	err = raw.Read(func(listenerFD uintptr) bool {
		for {
			fd, addr, acceptErr = unix.Accept4(int(listenerFD), unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK)
			if acceptErr != unix.EINTR {
				break
			}
		}
		return acceptErr != unix.EAGAIN && acceptErr != unix.EWOULDBLOCK
	})
	if err != nil {
		return nil, err
	}
	if acceptErr != nil {
		return nil, acceptErr
	}
	file := os.NewFile(uintptr(fd), "gcsrelay-vsock-peer")
	peer, ok := addr.(*unix.SockaddrVM)
	if !ok {
		file.Close()
		return nil, errors.New("gcsrelay: non-vsock peer address")
	}
	return &socket{file: file, local: l.addr, remote: &vsock.Addr{CID: peer.CID, Port: peer.Port}}, nil
}

func dialVSock(ctx context.Context, cid, port uint32) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	file, err := socketFile()
	if err != nil {
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() { file.Close() })
	defer stop()
	err = control(file, func(fd int) error {
		for {
			err := unix.Connect(fd, &unix.SockaddrVM{CID: cid, Port: port})
			if err != unix.EINTR {
				return err
			}
		}
	})
	if err == unix.EINPROGRESS {
		var raw syscall.RawConn
		raw, err = file.SyscallConn()
		if err == nil {
			first := true
			var connectErr error
			err = raw.Write(func(fd uintptr) bool {
				if first {
					first = false
					return false
				}
				code, e := unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_ERROR)
				connectErr = e
				if e == nil && code != 0 {
					connectErr = syscall.Errno(code)
				}
				return true
			})
			if err == nil {
				err = connectErr
			}
		}
	}
	var local unix.Sockaddr
	if err == nil {
		err = control(file, func(fd int) error {
			var e error
			local, e = unix.Getsockname(fd)
			return e
		})
	}
	if ctx.Err() != nil {
		err = ctx.Err()
	}
	if err != nil {
		file.Close()
		return nil, fmt.Errorf("dial CID%d port %#x: %w", cid, port, err)
	}
	addr, ok := local.(*unix.SockaddrVM)
	if !ok {
		file.Close()
		return nil, errors.New("gcsrelay: non-vsock local address")
	}
	return &socket{file: file, local: &vsock.Addr{CID: addr.CID, Port: addr.Port}, remote: &vsock.Addr{CID: cid, Port: port}}, nil
}

func (s *socket) Read(b []byte) (int, error)  { return s.file.Read(b) }
func (s *socket) Write(b []byte) (int, error) { return s.file.Write(b) }
func (s *socket) Close() error                { return s.file.Close() }
func (s *socket) LocalAddr() net.Addr         { return s.local }
func (s *socket) RemoteAddr() net.Addr        { return s.remote }
func (s *socket) CloseWrite() error {
	return control(s.file, func(fd int) error { return unix.Shutdown(fd, unix.SHUT_WR) })
}
func (s *socket) SetDeadline(t time.Time) error      { return s.file.SetDeadline(t) }
func (s *socket) SetReadDeadline(t time.Time) error  { return s.file.SetReadDeadline(t) }
func (s *socket) SetWriteDeadline(t time.Time) error { return s.file.SetWriteDeadline(t) }
