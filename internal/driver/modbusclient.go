// -*- Mode: Go; indent-tabs-mode: t -*-
//
// Copyright (C) 2018-2019 IOTech Ltd
//
// SPDX-License-Identifier: Apache-2.0

package driver

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	MODBUS "github.com/loyogo/modbus"
)

type DTUClientHandler struct {
	SlaveId byte
}
// ModbusClient is used for connecting the device and read/write value
type ModbusClient struct {
	// IsModbusTcp is a value indicating the connection type
	IsModbusTcp bool
	IsModbusDtu bool
	IsModbusRtu bool
	// TCPClientHandler is ued for holding device TCP connection
	TCPClientHandler MODBUS.TCPClientHandler
	// TCPClientHandler is ued for holding device RTU connection
	RTUClientHandler MODBUS.RTUClientHandler

	DTUClientHandler DTUClientHandler

	client MODBUS.Client
}

type dtuTransporter struct {
	// Connect string
	Address string
	// Connect & Read timeout
	Timeout time.Duration
	// Idle timeout to close the connection
	IdleTimeout time.Duration
	// Transmission logger
	Logger *log.Logger

	// TCP connection
	mu           sync.Mutex
	conn         net.Conn
	closeTimer   *time.Timer
	lastActivity time.Time
}
//func (mb *dtuTransporter) Send(aduRequest []byte) (aduResponse []byte, err error) {
//	mb.mu.Lock()
//	defer mb.mu.Unlock()
//
//	// Establish a new connection if not connected
//	//if err = mb.connect(); err != nil {
//	//	return
//	//}
//	// Set timer to close when idle
//	//mb.lastActivity = time.Now()
//	//mb.startCloseTimer()
//	// Set write and read timeout
//	var timeout time.Time
//	if mb.Timeout > 0 {
//		timeout = mb.lastActivity.Add(mb.Timeout)
//	}
//	if err = mb.conn.SetDeadline(timeout); err != nil {
//		return
//	}
//	// Send data
//	driver.Logger.Info("modbus: sending % x", aduRequest)
//	if _, err = mb.conn.Write(aduRequest); err != nil {
//		return
//	}
//	// Read header first
//	var data [tcpMaxLength]byte
//	if _, err = io.ReadFull(mb.conn, data[:tcpHeaderSize]); err != nil {
//		return
//	}
//	// Read length, ignore transaction & protocol id (4 bytes)
//	length := int(binary.BigEndian.Uint16(data[4:]))
//	if length <= 0 {
//		mb.flush(data[:])
//		err = fmt.Errorf("modbus: length in response header '%v' must not be zero", length)
//		return
//	}
//	if length > (tcpMaxLength - (tcpHeaderSize - 1)) {
//		mb.flush(data[:])
//		err = fmt.Errorf("modbus: length in response header '%v' must not greater than '%v'", length, tcpMaxLength-tcpHeaderSize+1)
//		return
//	}
//	// Skip unit id
//	length += tcpHeaderSize - 1
//	if _, err = io.ReadFull(mb.conn, data[tcpHeaderSize:length]); err != nil {
//		return
//	}
//	aduResponse = data[:length]
//	driver.Logger.Info("modbus: received % x\n", aduResponse)
//	return
//}


func (c *ModbusClient) OpenConnection() error {
	var err error
	var newClient MODBUS.Client
	if c.IsModbusTcp {
		err = c.TCPClientHandler.Connect()
		newClient = MODBUS.NewClient(&c.TCPClientHandler)
		driver.Logger.Info(fmt.Sprintf("Modbus client create TCP connection."))
	} else if c.IsModbusRtu {
		err = c.RTUClientHandler.Connect()
		newClient = MODBUS.NewClient(&c.RTUClientHandler)
		driver.Logger.Info(fmt.Sprintf("Modbus client create RTU connection."))
	} else {
		packagerFn := func(s byte) MODBUS.Packager { return MODBUS.NewRTUPackager(s) }
		newClient = MODBUS.NewClient2(packagerFn(c.DTUClientHandler.SlaveId),nil)
		driver.Logger.Info(fmt.Sprintf("Modbus client create DTU connection."))
	}
	c.client = newClient
	return err
}

func (c *ModbusClient) CloseConnection() error {
	var err error
	if c.IsModbusTcp {
		err = c.TCPClientHandler.Close()

	} else {
		err = c.RTUClientHandler.Close()
	}
	return err
}

func (c *ModbusClient) GetValue(commandInfo interface{}) ([]byte, error) {
	var modbusCommandInfo = commandInfo.(*CommandInfo)

	// Reading value from device
	var response []byte
	var err error

	switch modbusCommandInfo.PrimaryTable {
	case DISCRETES_INPUT:
		response, err = c.client.ReadDiscreteInputs(modbusCommandInfo.StartingAddress, modbusCommandInfo.Length)
	case COILS:
		response, err = c.client.ReadCoils(modbusCommandInfo.StartingAddress, modbusCommandInfo.Length)

	case INPUT_REGISTERS:
		response, err = c.client.ReadInputRegisters(modbusCommandInfo.StartingAddress, modbusCommandInfo.Length)
	case HOLDING_REGISTERS:
		response, err = c.client.ReadHoldingRegisters(modbusCommandInfo.StartingAddress, modbusCommandInfo.Length)
	default:
		driver.Logger.Error("None supported primary table! ")
	}

	if err != nil {
		return response, err
	}

	driver.Logger.Info(fmt.Sprintf("Modbus client GetValue's results %v", response))

	return response, nil
}

func (c *ModbusClient) SetValue(commandInfo interface{}, value []byte) error {
	var modbusCommandInfo = commandInfo.(*CommandInfo)

	// Write value to device
	var result []byte
	var err error

	switch modbusCommandInfo.PrimaryTable {
	case DISCRETES_INPUT:
		result, err = c.client.WriteMultipleCoils(uint16(modbusCommandInfo.StartingAddress), modbusCommandInfo.Length, value)

	case COILS:
		result, err = c.client.WriteMultipleCoils(uint16(modbusCommandInfo.StartingAddress), modbusCommandInfo.Length, value)

	case INPUT_REGISTERS:
		result, err = c.client.WriteMultipleRegisters(uint16(modbusCommandInfo.StartingAddress), modbusCommandInfo.Length, value)

	case HOLDING_REGISTERS:
		if modbusCommandInfo.Length == 1 {
			result, err = c.client.WriteSingleRegister(uint16(modbusCommandInfo.StartingAddress), binary.BigEndian.Uint16(value))
		} else {
			result, err = c.client.WriteMultipleRegisters(uint16(modbusCommandInfo.StartingAddress), modbusCommandInfo.Length, value)
		}
	default:
	}

	if err != nil {
		return err
	}
	driver.Logger.Info(fmt.Sprintf("Modbus client SetValue successful, results: %v", result))

	return nil
}

func NewDeviceClient(connectionInfo *ConnectionInfo) (*ModbusClient, error) {
	client := new(ModbusClient)
	var err error
	if connectionInfo.Protocol == ProtocolTCP {
		client.IsModbusTcp = true
		client.TCPClientHandler.Address = fmt.Sprintf("%s:%d", connectionInfo.Address, connectionInfo.Port)
		client.TCPClientHandler.SlaveId = byte(connectionInfo.UnitID)
		client.TCPClientHandler.IdleTimeout = 0
		client.TCPClientHandler.Logger = log.New(os.Stdout, "", log.LstdFlags)
	} else if connectionInfo.Protocol == ProtocolRTU {
		client.IsModbusRtu = true
		serialParams := strings.Split(connectionInfo.Address, ",")
		client.RTUClientHandler.Address = serialParams[0]
		client.RTUClientHandler.SlaveId = byte(connectionInfo.UnitID)
		client.RTUClientHandler.IdleTimeout = 0
		client.RTUClientHandler.BaudRate = connectionInfo.BaudRate
		client.RTUClientHandler.DataBits = connectionInfo.DataBits
		client.RTUClientHandler.StopBits = connectionInfo.StopBits
		client.RTUClientHandler.Parity = connectionInfo.Parity
		client.RTUClientHandler.Logger = log.New(os.Stdout, "", log.LstdFlags)
	} else {
		client.IsModbusDtu = true
		client.DTUClientHandler.SlaveId = byte(connectionInfo.UnitID)
	}
	return client, err
}
