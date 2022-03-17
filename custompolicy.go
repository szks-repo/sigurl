package sigurl

import "encoding/json"

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
			value: nil,
		},
		timeSlot: policy{
			xType: string(TimeSlotAny),
			value: nil,
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

func (cp *CustomPolicy) RegisterIpAddressPolicy(p ipAddressPolicy) error {
	cp.statement.ipAddress.xType = string(p)
	return nil
}

func (cp *CustomPolicy) RegisterTimeSlotPolicy(p timeSlotPolicy) error {
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
