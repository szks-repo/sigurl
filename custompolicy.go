package sigurl

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"time"
)

var (
	ErrCustomPolicyIllegalIPAddr   = errors.New("custom policy error: illegal ip address")
	ErrCustomPolicyIllegalTimeSlot = errors.New("custom policy error: illegal time slot")
)

type CustomPolicy struct {
	statement struct {
		ipAddress policy
		timeSlot  policy
	}
}

type policy struct {
	xType string
	value []string
}

type CustomPolicyFunc func(*CustomPolicy) error

func IPAddr(addr string) CustomPolicyFunc {
	return func(cp *CustomPolicy) error {
		switch ipAddressPolicy(cp.statement.ipAddress.xType) {
		case IpAddressAny:
			return nil
		case IpAddressAllow:
			for _, v := range cp.statement.ipAddress.value {
				if v == addr {
					return nil
				}
			}
			return fmt.Errorf("error ip address not allowed: %w", ErrCustomPolicyIllegalIPAddr)
		case IpAddressDeny:
			for _, v := range cp.statement.ipAddress.value {
				if v == addr {
					return fmt.Errorf("error ip denied ip addr: %w", ErrCustomPolicyIllegalIPAddr)
				}
			}
			return nil
		}

		return fmt.Errorf("error unexpected case: %w", ErrCustomPolicyIllegalIPAddr)
	}
}

func TimeSlot(now time.Time) CustomPolicyFunc {
	return func(cp *CustomPolicy) error {
		switch timeSlotPolicy(cp.statement.timeSlot.xType) {
		case TimeSlotAny:
			return nil
		case TimeSlotCheck:
			//Todo:
			return nil
		}

		return fmt.Errorf("out of time slot: %w", ErrCustomPolicyIllegalTimeSlot)
	}
}

func NewCustomPolicy() *CustomPolicy {
	return &CustomPolicy{statement: struct {
		ipAddress policy
		timeSlot  policy
	}{
		ipAddress: policy{
			xType: string(IpAddressAny),
			value: []string{},
		},
		timeSlot: policy{
			xType: string(TimeSlotAny),
			value: []string{},
		},
	}}
}

type (
	ipAddressPolicy string
	timeSlotPolicy  string
)

const (
	IpAddressAny   ipAddressPolicy = "Any"
	IpAddressAllow ipAddressPolicy = "Allow"
	IpAddressDeny  ipAddressPolicy = "Deny"
	TimeSlotAny    timeSlotPolicy  = "Any"
	TimeSlotCheck  timeSlotPolicy  = "Check"
)

func (cp *CustomPolicy) RegisterIpAddressPolicy(p ipAddressPolicy, value []string) error {
	if p == IpAddressAny {
		cp.statement.ipAddress.xType = string(p)
		return nil
	}

	var addrs []string
	for _, v := range value {
		addr, err := netip.ParseAddr(v)
		if err != nil {
			return err
		}
		if addr.IsLoopback() {
			return errors.New("loop back address is not supported")
		}
		addrs = append(addrs, addr.String())
	}
	if len(addrs) == 0 {
		return errors.New("value len must be greater than 0")
	}

	cp.statement.ipAddress.xType = string(p)
	cp.statement.ipAddress.value = addrs
	return nil
}

func (cp *CustomPolicy) RegisterTimeSlotPolicy(p timeSlotPolicy, start, end string) error {
	if p == TimeSlotAny {
		cp.statement.timeSlot.xType = string(p)
		return nil
	}
	//Todo:
	cp.statement.timeSlot.xType = string(p)

	return nil
}

func (cp *CustomPolicy) JSONMarshal() ([]byte, error) {
	return json.Marshal(struct {
		Statement struct {
			IpAddress struct {
				Type  string
				Value []string
			}
			TimeSlot struct {
				Type  string
				Value []string
			}
		}
	}{
		Statement: struct {
			IpAddress struct {
				Type  string
				Value []string
			}
			TimeSlot struct {
				Type  string
				Value []string
			}
		}{
			IpAddress: struct {
				Type  string
				Value []string
			}{
				Type:  cp.statement.ipAddress.xType,
				Value: cp.statement.ipAddress.value,
			},
			TimeSlot: struct {
				Type  string
				Value []string
			}{
				Type:  cp.statement.timeSlot.xType,
				Value: cp.statement.timeSlot.value,
			},
		},
	})
}
