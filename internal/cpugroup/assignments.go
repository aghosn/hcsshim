//go:build windows

package cpugroup

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/Microsoft/go-winio/pkg/guid"
	hcsschema "github.com/Microsoft/hcsshim/internal/hcs/schema2"
)

type Operations struct {
	Create      func(context.Context, string, []uint32) error
	SetPriority func(context.Context, string, uint32) error
	Query       func(context.Context, string) (*hcsschema.CpuGroupConfig, error)
	Delete      func(context.Context, string) error
}

var HostOperations = Operations{
	Create: Create, SetPriority: SetSchedulingPriority, Query: GetCPUGroupConfig, Delete: Delete,
}

type Report struct {
	GroupID            string   `json:"group_id"`
	LogicalProcessors  []uint32 `json:"logical_processors"`
	SchedulingPriority uint32   `json:"scheduling_priority"`
}

// Assignments owns only the groups created for this set of VM affinities.
type Assignments struct {
	IDs     []string
	Reports []Report
	owned   []string
	ops     Operations
}

func CanonicalLPs(lps []uint32) ([]uint32, string, error) {
	if len(lps) == 0 {
		return nil, "", errors.New("CPU affinity cannot be empty")
	}
	ordered := append([]uint32(nil), lps...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i] < ordered[j] })
	parts := make([]string, len(ordered))
	for i, lp := range ordered {
		if lp > 1<<31-1 || (i > 0 && ordered[i-1] == lp) {
			return nil, "", fmt.Errorf("invalid or duplicate logical processor %d", lp)
		}
		parts[i] = strconv.FormatUint(uint64(lp), 10)
	}
	return ordered, strings.Join(parts, ","), nil
}

// Prepare validates all affinities before creating groups. Identical affinities
// share a group unless independent scheduling priorities were requested.
// A nil affinity leaves that VM's inherited group unchanged.
func Prepare(ctx context.Context, groups [][]uint32, vmCount int, ops Operations, priorities ...uint32) (_ *Assignments, resultErr error) {
	assignments := &Assignments{ops: ops}
	if len(priorities) != 0 {
		if len(groups) == 0 || len(priorities) != vmCount {
			return nil, fmt.Errorf("CPU group priorities require CPU affinity and exactly %d VM priorities", vmCount)
		}
		for _, priority := range priorities {
			if priority > MaxSchedulingPriority {
				return nil, fmt.Errorf("CPU group scheduling priority %d exceeds %d", priority, MaxSchedulingPriority)
			}
		}
	}
	if len(groups) == 0 {
		return assignments, nil
	}
	if len(groups) != vmCount {
		return nil, fmt.Errorf("CPU affinity has %d VM lists, expected %d", len(groups), vmCount)
	}
	ordered := make([][]uint32, len(groups))
	keys := make([]string, len(groups))
	lpOwners := map[uint32]string{}
	for i, group := range groups {
		if group == nil {
			if len(priorities) != 0 {
				return nil, errors.New("CPU group priorities require affinity for every VM")
			}
			continue
		}
		var err error
		ordered[i], keys[i], err = CanonicalLPs(group)
		if err != nil {
			return nil, err
		}
		for _, lp := range ordered[i] {
			if owner, ok := lpOwners[lp]; ok && owner != keys[i] {
				return nil, fmt.Errorf("partially overlapping CPU affinities: %s and %s", owner, keys[i])
			}
			lpOwners[lp] = keys[i]
		}
	}
	defer func() {
		if resultErr != nil {
			resultErr = errors.Join(resultErr, assignments.Close(context.WithoutCancel(ctx)))
		}
	}()
	created := map[string]string{}
	for i, lps := range ordered {
		if lps == nil {
			assignments.IDs = append(assignments.IDs, "")
			continue
		}
		if id, ok := created[keys[i]]; ok && len(priorities) == 0 {
			assignments.IDs = append(assignments.IDs, id)
			continue
		}
		id, err := guid.NewV4()
		if err != nil {
			return nil, fmt.Errorf("allocate CPU group ID: %w", err)
		}
		if err := ops.Create(ctx, id.String(), lps); err != nil {
			return nil, fmt.Errorf("create CPU affinity %s: %w", keys[i], err)
		}
		assignments.owned = append(assignments.owned, id.String())
		if len(priorities) != 0 {
			if err := ops.SetPriority(ctx, id.String(), priorities[i]); err != nil {
				return nil, fmt.Errorf("set CPU group %s scheduling priority: %w", id, err)
			}
		}
		config, err := ops.Query(ctx, id.String())
		if err != nil {
			return nil, fmt.Errorf("verify CPU group %s: %w", id, err)
		}
		if config == nil || config.Affinity == nil {
			return nil, fmt.Errorf("CPU group %s returned no affinity", id)
		}
		actual := make([]uint32, len(config.Affinity.LogicalProcessors))
		for j, lp := range config.Affinity.LogicalProcessors {
			if lp < 0 {
				return nil, fmt.Errorf("CPU group %s returned negative LP %d", id, lp)
			}
			actual[j] = uint32(lp)
		}
		_, actualKey, err := CanonicalLPs(actual)
		if err != nil || actualKey != keys[i] || config.Affinity.LogicalProcessorCount != int32(len(lps)) {
			return nil, fmt.Errorf("CPU group %s affinity mismatch: requested %s, got %+v", id, keys[i], config.Affinity)
		}
		if len(priorities) != 0 {
			if !strings.EqualFold(config.GroupId, id.String()) {
				return nil, fmt.Errorf("CPU group %s returned mismatched group ID %q", id, config.GroupId)
			}
			found := false
			for _, property := range config.GroupProperties {
				if property.PropertyCode == hcsschema.CPUSchedulingPriorityProperty {
					if found || property.PropertyValue != priorities[i] {
						return nil, fmt.Errorf("CPU group %s scheduling priority mismatch: requested %d, got %+v", id, priorities[i], config.GroupProperties)
					}
					found = true
				}
			}
			if !found {
				return nil, fmt.Errorf("CPU group %s returned no scheduling priority", id)
			}
			assignments.Reports = append(assignments.Reports, Report{
				GroupID: config.GroupId, LogicalProcessors: actual, SchedulingPriority: priorities[i],
			})
		}
		created[keys[i]] = id.String()
		assignments.IDs = append(assignments.IDs, id.String())
	}
	return assignments, nil
}

func (a *Assignments) Close(ctx context.Context) error {
	var result error
	for i := len(a.owned) - 1; i >= 0; i-- {
		if err := a.ops.Delete(ctx, a.owned[i]); err != nil {
			result = errors.Join(result, fmt.Errorf("delete CPU group %s: %w", a.owned[i], err))
		}
	}
	a.owned = nil
	return result
}
