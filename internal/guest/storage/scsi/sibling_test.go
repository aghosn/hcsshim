//go:build linux

package scsi

import (
	"context"
	"testing"
	"testing/fstest"
)

func TestSiblingControllerNumber(t *testing.T) {
	const device = "sys/bus/vmbus/devices/"
	const storage = "bus1-relid2-00000001-0000-0000-0000-000000000000/"
	const other = "bus2-relid2-00000001-0000-0000-0000-000000000000/"
	for _, tc := range []struct {
		name string
		sys  fstest.MapFS
		want uint8
		fail bool
	}{
		{
			name: "sibling beside RP",
			sys: fstest.MapFS{
				device + "11111111-2222-3333-4444-555555555555/host0":                {},
				device + storage + "class_id":                                        {Data: []byte("{" + siblingStorageClass + "}\n")},
				device + storage + "host4":                                           {},
				device + "bus1-relid1-00000002-0000-0000-0000-000000000000/class_id": {Data: []byte("{f8615163-df3e-46c5-913f-f2d2f965ed0e}\n")},
			},
			want: 4,
		},
		{
			name: "truncated peer name is not a device",
			sys: fstest.MapFS{
				device + "bus1-relid2/class_id": {Data: []byte(siblingStorageClass)},
				device + "bus1-relid2/host4":    {},
			},
			fail: true,
		},
		{
			name: "RP is not fallback",
			sys:  fstest.MapFS{device + "11111111-2222-3333-4444-555555555555/host0": {}},
			fail: true,
		},
		{
			name: "missing SCSI host",
			sys:  fstest.MapFS{device + storage + "class_id": {Data: []byte(siblingStorageClass)}},
			fail: true,
		},
		{
			name: "invalid host",
			sys: fstest.MapFS{
				device + storage + "class_id": {Data: []byte(siblingStorageClass)},
				device + storage + "host256":  {},
			},
			fail: true,
		},
		{
			name: "ambiguous",
			sys: fstest.MapFS{
				device + storage + "class_id": {Data: []byte(siblingStorageClass)},
				device + storage + "host4":    {},
				device + other + "class_id":   {Data: []byte(siblingStorageClass)},
				device + other + "host5":      {},
			},
			fail: true,
		},
		{
			name: "unreadable class",
			sys:  fstest.MapFS{device + storage + "host4": {}},
			fail: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := siblingControllerNumber(tc.sys)
			if (err != nil) != tc.fail || (!tc.fail && got != tc.want) {
				t.Fatalf("got %d, %v; want %d, failure=%v", got, err, tc.want, tc.fail)
			}
		})
	}
}

func TestResolveControllerNumberRejectsInvalidController(t *testing.T) {
	for _, sibling := range []bool{false, true} {
		if _, err := ResolveControllerNumber(context.Background(), 255, sibling); err == nil {
			t.Fatalf("accepted controller 255, sibling=%v", sibling)
		}
	}
}
