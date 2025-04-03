// Copyright 2019 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package linux

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"strings"

	"github.com/google/syzkaller/prog"
)

const (
	USB_DEVICE_ID_MATCH_VENDOR = 1 << iota
	USB_DEVICE_ID_MATCH_PRODUCT
	USB_DEVICE_ID_MATCH_DEV_LO
	USB_DEVICE_ID_MATCH_DEV_HI
	USB_DEVICE_ID_MATCH_DEV_CLASS
	USB_DEVICE_ID_MATCH_DEV_SUBCLASS
	USB_DEVICE_ID_MATCH_DEV_PROTOCOL
	USB_DEVICE_ID_MATCH_INT_CLASS
	USB_DEVICE_ID_MATCH_INT_SUBCLASS
	USB_DEVICE_ID_MATCH_INT_PROTOCOL
	USB_DEVICE_ID_MATCH_INT_NUMBER

	BytesPerUsbID = 17
	BytesPerHidID = 12
)

type UsbDeviceID struct {
	MatchFlags         uint16
	IDVendor           uint16
	IDProduct          uint16
	BcdDeviceLo        uint16
	BcdDeviceHi        uint16
	BDeviceClass       uint8
	BDeviceSubClass    uint8
	BDeviceProtocol    uint8
	BInterfaceClass    uint8
	BInterfaceSubClass uint8
	BInterfaceProtocol uint8
	BInterfaceNumber   uint8
}

type HidDeviceID struct {
	Bus     uint16
	Group   uint16
	Vendor  uint32
	Product uint32
}

func (arch *arch) generateUsbDeviceDescriptor(g *prog.Gen, typ0 prog.Type, dir prog.Dir, old prog.Arg) (
	arg prog.Arg, calls []*prog.Call) {
	if old == nil {
		arg = g.GenerateSpecialArg(typ0, dir, &calls)
	} else {
		arg = prog.CloneArg(old)
		calls = g.MutateArg(arg)
	}
	if g.Target().ArgContainsAny(arg) {
		return
	}

	id := randUsbDeviceID(g)
	bcdDevice := id.BcdDeviceLo + uint16(g.Rand().Intn(int(id.BcdDeviceHi-id.BcdDeviceLo)+1))

	devArg := arg.(*prog.GroupArg).Inner[0]
	patchGroupArg(devArg, 7, "idVendor", uint64(id.IDVendor))
	patchGroupArg(devArg, 8, "idProduct", uint64(id.IDProduct))
	// hardcode for anton touchpad
	// patchGroupArg(devArg, 7, "idVendor", uint64(0x1130))
	// patchGroupArg(devArg, 8, "idProduct", uint64(0x3101))
	patchGroupArg(devArg, 9, "bcdDevice", uint64(bcdDevice))
	patchGroupArg(devArg, 3, "bDeviceClass", uint64(id.BDeviceClass))
	patchGroupArg(devArg, 4, "bDeviceSubClass", uint64(id.BDeviceSubClass))
	patchGroupArg(devArg, 5, "bDeviceProtocol", uint64(id.BDeviceProtocol))

	configArg := devArg.(*prog.GroupArg).Inner[14].(*prog.GroupArg).Inner[0].(*prog.GroupArg).Inner[0]
	interfacesArg := configArg.(*prog.GroupArg).Inner[8]

	for i, interfaceArg := range interfacesArg.(*prog.GroupArg).Inner {
		interfaceArg = interfaceArg.(*prog.GroupArg).Inner[0]
		if i > 0 {
			// Generate new IDs for every interface after the first one.
			id = randUsbDeviceID(g)
		}
		patchGroupArg(interfaceArg, 5, "bInterfaceClass", uint64(id.BInterfaceClass))
		patchGroupArg(interfaceArg, 6, "bInterfaceSubClass", uint64(id.BInterfaceSubClass))
		patchGroupArg(interfaceArg, 7, "bInterfaceProtocol", uint64(id.BInterfaceProtocol))
		patchGroupArg(interfaceArg, 2, "bInterfaceNumber", uint64(id.BInterfaceNumber))
	}

	return
}

func randUsbDeviceID(g *prog.Gen) UsbDeviceID {
	totalIds := len(usbIds) / BytesPerUsbID
	idNum := g.Rand().Intn(totalIds)
	base := usbIds[idNum*BytesPerUsbID : (idNum+1)*BytesPerUsbID]

	p := strings.NewReader(base)
	var id UsbDeviceID
	if binary.Read(p, binary.LittleEndian, &id) != nil {
		panic("not enough data to read")
	}

	if (id.MatchFlags & USB_DEVICE_ID_MATCH_VENDOR) == 0 {
		id.IDVendor = uint16(g.Rand().Intn(0xffff + 1))
	}
	if (id.MatchFlags & USB_DEVICE_ID_MATCH_PRODUCT) == 0 {
		id.IDProduct = uint16(g.Rand().Intn(0xffff + 1))
	}
	if (id.MatchFlags & USB_DEVICE_ID_MATCH_DEV_LO) == 0 {
		id.BcdDeviceLo = 0x0
	}
	if (id.MatchFlags & USB_DEVICE_ID_MATCH_DEV_HI) == 0 {
		id.BcdDeviceHi = 0xffff
	}
	if (id.MatchFlags & USB_DEVICE_ID_MATCH_DEV_CLASS) == 0 {
		id.BDeviceClass = uint8(g.Rand().Intn(0xff + 1))
	}
	if (id.MatchFlags & USB_DEVICE_ID_MATCH_DEV_SUBCLASS) == 0 {
		id.BDeviceSubClass = uint8(g.Rand().Intn(0xff + 1))
	}
	if (id.MatchFlags & USB_DEVICE_ID_MATCH_DEV_PROTOCOL) == 0 {
		id.BDeviceProtocol = uint8(g.Rand().Intn(0xff + 1))
	}
	if (id.MatchFlags & USB_DEVICE_ID_MATCH_INT_CLASS) == 0 {
		id.BInterfaceClass = uint8(g.Rand().Intn(0xff + 1))
	}
	if (id.MatchFlags & USB_DEVICE_ID_MATCH_INT_SUBCLASS) == 0 {
		id.BInterfaceSubClass = uint8(g.Rand().Intn(0xff + 1))
	}
	if (id.MatchFlags & USB_DEVICE_ID_MATCH_INT_PROTOCOL) == 0 {
		id.BInterfaceProtocol = uint8(g.Rand().Intn(0xff + 1))
	}
	if (id.MatchFlags & USB_DEVICE_ID_MATCH_INT_NUMBER) == 0 {
		id.BInterfaceNumber = uint8(g.Rand().Intn(0xff + 1))
	}

	return id
}

func (arch *arch) generateUsbHidDeviceDescriptor(g *prog.Gen, typ0 prog.Type, dir prog.Dir, old prog.Arg) (
	arg prog.Arg, calls []*prog.Call) {
	if old == nil {
		arg = g.GenerateSpecialArg(typ0, dir, &calls)
	} else {
		arg = prog.CloneArg(old)
		calls = g.MutateArg(arg)
	}
	if g.Target().ArgContainsAny(arg) {
		return
	}

	totalIds := len(hidIds) / BytesPerHidID
	idNum := g.Rand().Intn(totalIds)
	base := hidIds[idNum*BytesPerHidID : (idNum+1)*BytesPerHidID]

	p := strings.NewReader(base)
	var id HidDeviceID
	if binary.Read(p, binary.LittleEndian, &id) != nil {
		panic("not enough data to read")
	}

	devArg := arg.(*prog.GroupArg).Inner[0]
	patchGroupArg(devArg, 7, "idVendor", uint64(id.Vendor))
	patchGroupArg(devArg, 8, "idProduct", uint64(id.Product))
	// hardcode for anton touchpad
	// patchGroupArg(devArg, 7, "idVendor", uint64(0x1130))
	// patchGroupArg(devArg, 8, "idProduct", uint64(0x3101))

	return
}

// ******************************

func generateUsagePage() (byte, byte) {
	// 0x05 = 0b000001nn where nn is 01 for one byte
	// see pages 14 and 35 of hid1_11.pdf
	return 0x05, byte(rand.Uint32() & 0xFF)
}

func generateUsage() (byte, byte) {
	// 0x09 = 0b000010nn where nn is 01 for one byte
	// see pages 14 and 40 of hid1_11.pdf
	return 0x09, byte(rand.Uint32() & 0xFF)
}

func generateCollection() (byte, byte) {
	// 0xA1 = 0b101000nn where nn is 01 for one byte
	// see pages 14 and 28 of hid1_11.pdf
	return 0xA1, byte(rand.Uint32() & 0x07)
}

func generateEndCollection() byte {
	// 0xC0 = 0b11000000
	// see pages 14 and 28 of hid1_11.pdf
	return 0xC0
}

func generateReportDescriptor(len int) []byte {
	descriptor := make([]byte, len)
	if len < 7 {
		fmt.Println("TODO")
	} else {
		descriptor[0], descriptor[1] = generateUsagePage()
		descriptor[2], descriptor[3] = generateUsage()
		descriptor[4], descriptor[5] = generateCollection()
		descriptor[len-1] = generateEndCollection()

		descriptor[6] = chooseItem(0xff)
		for i := 7; i < len-2; i = i + 2 {
			descriptor[i] = byte(rand.Uint32() & 0xFF)
			descriptor[i+1] = chooseItem(descriptor[i-1])
		}
	}
	return descriptor
}

// All items will have a single byte value
func chooseItem(prev byte) byte {
	items := []byte{
		0x81, // Input
		0x91, // Output
		0xB1, // Feature
		0x05, // Usage Page
		0x09, // Usage
		0x85, // Report ID
		0x95, // Report Count
		0x75, // Report Size
	}
	transitions := map[byte][]uint{
		0xff: {0, 0, 0, 1, 1, 8, 0, 0}, //first transition

		0x81: {0, 0, 0, 1, 4, 4, 1, 0},
		0x91: {0, 0, 0, 1, 4, 4, 1, 0},
		0xB1: {0, 0, 0, 1, 4, 4, 1, 0},
		0x05: {0, 0, 0, 0, 6, 0, 2, 2},
		0x09: {0, 0, 0, 0, 0, 5, 0, 5},
		0x85: {0, 0, 0, 3, 3, 0, 2, 2},
		0x95: {0, 0, 1, 0, 0, 0, 0, 9},
		0x75: {3, 3, 4, 0, 0, 0, 0, 0},
	}

	transition := transitions[prev]
	fmt.Println(transition)
	choices := []byte{}
	for i, v := range transition {
		for j := 0; j < int(v); j++ {
			choices = append(choices, items[i])
		}
	}
	fmt.Println(choices)
	choice := rand.Intn(10)
	return choices[choice]
}

func (arch *arch) generateDescriptorsHID(g *prog.Gen, typ0 prog.Type, dir prog.Dir, old prog.Arg) (
	arg prog.Arg, calls []*prog.Call) {

	if old == nil {
		//fmt.Println("GENERATING SPECIAL ARG")
		arg = g.GenerateSpecialArg(typ0, dir, &calls)
	} else {
		//fmt.Println("MUTATING ARG")
		arg = prog.CloneArg(old)
		calls = g.MutateArg(arg)
	}
	if g.Target().ArgContainsAny(arg) {
		//fmt.Println("EARLY RETURN")
		return
	}

	/*
		# arg == hid_descriptor_report as a GroupArg
		hid_descriptor_report {
			# items is arg.Inner where each element is a UnionArg
			items	array[hid_report_item_short]
		} [packed]

		# The Option of those UnionArgs will be another UnionArg (see hid_report_item_short_t in vusb.txt)
		# That nested UnionArg will then be a GroupArg
		hid_report_item_short [
			main	hid_report_item_short_t[HID_ITEM_TYPE_MAIN, hid_report_item_main_tags]
			global	hid_report_item_short_t[HID_ITEM_TYPE_GLOBAL, hid_report_item_global_tags]
			local	hid_report_item_short_t[HID_ITEM_TYPE_LOCAL, hid_report_item_local_tags]
		] [varlen]
	*/

	/*
		The implementation above would be difficult to patch out.
		More details can be found in a vusb.txt near the modified structures

		Instead, the hid_descriptor_report is modified to be a buffer of int8s
		hid_descriptor_report {
			items	array[int8, 21:256]
		} [packed]
	*/

	a := arg.(*prog.GroupArg).Inner[3]
	//typ := arg.Type().(*prog.StructType)
	//fmt.Println("DEBUGG: ", typ.Fields[3].Name)

	data := a.(*prog.PointerArg).Res.(*prog.GroupArg).Inner[3]
	//dtyp := a.(*prog.PointerArg).Res.Type().(*prog.StructType)
	//fmt.Println("DEBUGG: ", dtyp.Fields[3].Name)

	items := data.(*prog.GroupArg).Inner[0]
	//That structure is a DataArg
	len := items.(*prog.DataArg).Size()

	report_descriptor := generateReportDescriptor(int(len))
	items.(*prog.DataArg).SetData(report_descriptor)
	return
}

func patchGroupArg(arg prog.Arg, index int, field string, value uint64) {
	a := arg.(*prog.GroupArg)
	typ := a.Type().(*prog.StructType)
	if field != typ.Fields[index].Name {
		panic(fmt.Sprintf("bad field, expected %v, found %v", field, typ.Fields[index].Name))
	}
	a.Inner[index].(*prog.ConstArg).Val = value
}
