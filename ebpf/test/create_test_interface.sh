#!/bin/bash

# Check if the script is run as root
if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit
fi

# Name of the test interface
TEST_INTERFACE="test0"
PEER_INTERFACE="test1"

# Create the veth pair
ip link add $TEST_INTERFACE type veth peer name $PEER_INTERFACE

# Bring up both interfaces
ip link set dev $TEST_INTERFACE up
ip link set dev $PEER_INTERFACE up

# Assign IP addresses (optional, but can be useful)
ip addr add 192.168.100.1/24 dev $TEST_INTERFACE
ip addr add 192.168.100.2/24 dev $PEER_INTERFACE

echo "Test interface $TEST_INTERFACE and its peer $PEER_INTERFACE have been created and brought up."
echo "You can now use $TEST_INTERFACE for your XDP program testing."