package sigurl

import (
	"encoding/json"
	"errors"
	"net/netip"
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
