// Thomas Karpiniec, 1 Sep 2017
// Companion code to https://karp.id.au/a/2017/09/01/layer-2-raw-sockets-on-rustlinux/

extern crate libc;
use std::io;
use std::ptr;
use std::mem;
use std::collections::HashMap;
use std::net::Ipv4Addr;

use libc::{sockaddr_ll, sockaddr, recvfrom, c_void, socklen_t,
           socket, AF_PACKET, SOCK_RAW, sendto};

const ETH_P_ARP: u16 = 0x0806; // from if_ether.h for SOCK_RAW
const OP_REQUEST: u16 = 1;
const OP_REPLY: u16 = 2;

type Mappings = HashMap<Ipv4Addr, MacAddr>;
type MacAddr = [u8; 6];

/// An ARP packet with ethernet headers still attached
#[repr(C)]
#[derive(Debug)]
struct RawArpFrame {
    // Ethernet frame headers
    destination_mac: [u8; 6],
    source_mac: [u8; 6],
    ether_type: u16, // should be 0x0806 BE for an ARP payload

    // ARP Payload
    hardware_type: u16, // expect 0x0001 for ethernet
    protocol_type: u16, // expect 0x0800 for IPv4
    hw_addr_len: u8, // expect 6 [octets] for MAC addresses
    proto_addr_len: u8, // expect 4 [octets] for IPv4 addresses
    operation: u16, // 1 for request, 2 for reply
    sender_hw_addr: [u8; 6],
    sender_proto_addr: [u8; 4],
    target_hw_addr: [u8; 6],
    target_proto_addr: [u8; 4]
}

/// Wait for a single packet on the fd, reading it into a buffer. Also writes the sockaddr
/// into the structure provided as a mutable parameter.
fn recv_single_packet(fd: i32, addr: &mut sockaddr_ll, buf: &mut [u8]) -> io::Result<usize> {
    let len: isize;
    let mut addr_buf_sz: socklen_t = mem::size_of::<sockaddr_ll>() as socklen_t;
    unsafe {
        let addr_ptr = mem::transmute::<*mut sockaddr_ll, *mut sockaddr>(addr);
        len = match recvfrom(fd, // file descriptor
                             buf.as_mut_ptr() as *mut c_void, // pointer to buffer for frame content
                             buf.len(), // frame content buffer length
                             0, // flags
                             addr_ptr as *mut sockaddr, // pointer to buffer for sender address
                             &mut addr_buf_sz) { // sender address buffer length
            -1 => {
                return Err(io::Error::last_os_error());
            },
            len => len
        };
    }

    // Return the number of valid bytes that were placed in the buffer
    Ok(len as usize)
}

/// Process incoming ARP packets in a loop until an error occurs.
fn listen_for_arp_requests(mappings: &Mappings) -> io::Result<()> {
    let mut sender_addr: sockaddr_ll = unsafe { mem::zeroed() };
    let mut packet_buf: [u8; 1024] = [0; 1024];

    let fd = open_fd()?;

    loop {
        match recv_single_packet(fd, &mut sender_addr, &mut packet_buf) {
            Ok(len) => handle_packet(fd, mappings, sender_addr, &packet_buf[0..len]),
            Err(e) => return Err(e)
        }
    }
}

/// Open a raw AF_PACKET socket for the ARP protocol.
fn open_fd() -> io::Result<i32> {
    unsafe {
        match socket(AF_PACKET, SOCK_RAW, ETH_P_ARP.to_be() as i32) {
            -1 => Err(io::Error::last_os_error()),
            fd => Ok(fd)
        }
    }
}

/// Given a buffer for a received ARP packet, parse it and consider replying
fn handle_packet(fd: i32, mappings: &Mappings, sender: sockaddr_ll, packet: &[u8]) {
    if packet.len() < mem::size_of::<RawArpFrame>() {
        // Ignore frame that was too short
        return;
    }
    // We can't trust any of this data but assume all fields lined up correctly
    // Worst case we'll send some response that makes no sense
    let parsed: RawArpFrame = unsafe { ptr::read(packet.as_ptr() as *const _) };

    // Sanity check 1 - is the ether type correct?
    if parsed.ether_type.to_be() != 0x0806 {
        return;
    }
    // Is this a request?
    if parsed.operation.to_be() != OP_REQUEST {
        return;
    }

    // Now let's see if it's one of ours
    let tpa = Ipv4Addr::new(parsed.target_proto_addr[0],
                            parsed.target_proto_addr[1],
                            parsed.target_proto_addr[2],
                            parsed.target_proto_addr[3]);
    println!("Saw ARP request for IP address {}", tpa);

    match mappings.get(&tpa) {
        Some(&mac_addr) => send_reply(fd, parsed, mac_addr, sender),
        _ => return
    }
}

/// Given a received parsed ARP frame, send a reply supplying a particular MAC address.
fn send_reply(fd: i32, mut frame: RawArpFrame, mac_addr: MacAddr, raw_addr: sockaddr_ll) {
    // First, modify the the request payload into a reply and send it
    frame.destination_mac = frame.source_mac;
    frame.source_mac = mac_addr; // pretend to be the machine queried at the Ethernet layer
    frame.operation = OP_REPLY.to_be();

    let target_addr = frame.target_proto_addr;
    frame.target_proto_addr = frame.sender_proto_addr;
    frame.target_hw_addr = frame.sender_hw_addr;
    frame.sender_hw_addr = mac_addr;
    frame.sender_proto_addr = target_addr;

    // For simplicity, re-use fields from the sockaddr_ll we got when we received the request.
    // This includes "ifindex". Keeping it the same means we will reply on the same interface.
    // Otherwise a SIOCGIFINDEX ioctl is needed to get the number.
    let mut sa = sockaddr_ll {
        sll_family: raw_addr.sll_family,
        sll_protocol: raw_addr.sll_protocol,
        sll_ifindex: raw_addr.sll_ifindex,
        sll_hatype: 0,
        sll_pkttype: 0,
        sll_halen: 0,
        sll_addr: [0; 8]
    };

    unsafe {
        let addr_ptr = mem::transmute::<*mut sockaddr_ll, *mut sockaddr>(&mut sa);
        match sendto(fd, &mut frame as *mut _ as *const c_void, mem::size_of_val(&frame),
                     0, addr_ptr, mem::size_of_val(&sa) as u32)
            {
                d if d < 0 => println!("Error sending reply"),
                _ => println!("Sent an ARP reply")
            }
    }
}

fn main() {
    println!("ARP Server Launched");

    let mut mappings: Mappings = HashMap::new();
    mappings.insert(Ipv4Addr::new(10, 130, 1, 103), [0x00, 0x01, 0x02, 0x03, 0x04, 0x05] );
    mappings.insert(Ipv4Addr::new(10, 130, 1, 104), [0x10, 0x11, 0x12, 0x13, 0x14, 0x15] );

    match listen_for_arp_requests(&mappings) {
        Ok(_) => return,
        Err(e) => println!("Error: {}", e)
    }
}