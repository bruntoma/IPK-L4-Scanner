using System;
using System.Linq;
using System.Net;
using System.Net.Sockets;

namespace IPK_L4_Scanner.Packets;

public class IcmpPacket : Packet
{
    public byte Type { get; private set; }
    public byte Code { get; private set; }
    public ushort Checksum { get; private set; }
    public byte[] Data { get; private set; }
    public bool IsIpv6 { get; private set; }
    
    private const byte ICMP_HEADER_LENGTH = 8;
    
    public IcmpPacket(byte type, byte code, byte[] data, bool isIpv6)
        : base(ICMP_HEADER_LENGTH)
    {
        this.Type = type;
        this.Code = code;
        this.Data = data;
        this.IsIpv6 = isIpv6;
        
        // Create the bytes for the ICMP packet
        this.Bytes = new byte[ICMP_HEADER_LENGTH + data.Length];
        this.Bytes[0] = type;
        this.Bytes[1] = code;
        
        // Copy the data after the header
        if (data.Length > 0)
        {
            Array.Copy(data, 0, this.Bytes, ICMP_HEADER_LENGTH, data.Length);
        }
    }
    
    public static IcmpPacket? FromBytes(byte[] packet, IPAddress sourceIp, IPAddress destinationIp)
{
    if (packet.Length < 28) // Min size for IPv4(20) + ICMP(8)
    {
        Console.WriteLine("Packet too short to parse ICMP header.");
        return null;
    }
    
    // Calculate ICMP header offset
    // For IPv4, offset is the IP header length
    // For IPv6, we receive only the ICMP header (offset 0)
    int icmpHeaderOffset = (destinationIp.AddressFamily == AddressFamily.InterNetwork) ? (packet[0] & 0x0F) * 4 : 0;
    
    // Extract ICMP fields
    byte type = packet[icmpHeaderOffset];
    byte code = packet[icmpHeaderOffset + 1];
    
    // Create data array from everything after the ICMP header
    byte[] data = new byte[packet.Length - icmpHeaderOffset - ICMP_HEADER_LENGTH];
    if (data.Length > 0)
    {
        Array.Copy(packet, icmpHeaderOffset + ICMP_HEADER_LENGTH, data, 0, data.Length);
    }
    
    bool isIpv6 = sourceIp.AddressFamily == AddressFamily.InterNetworkV6;
    return new IcmpPacket(type, code, data, isIpv6);
}
    
  // Get the original UDP packet that triggered this ICMP error response
public UdpPacket? GetOriginalUdpPacket()
{
    try
    {
        // The Data field contains the original IP+UDP packet
        if (Data == null || Data.Length < 28) // At minimum we need IP header + UDP header
            return null;
            
        // Extract the source and destination IPs from the embedded IP header
        IPAddress? sourceIp = null;
        IPAddress? destIp = null;
        
        if (IsIpv6)
        {
            // For IPv6, addresses are at offsets 8 and 24
            if (Data.Length >= 40) // Ensure we have a complete IPv6 header
            {
                byte[] srcBytes = new byte[16];
                byte[] dstBytes = new byte[16];
                Array.Copy(Data, 8, srcBytes, 0, 16);
                Array.Copy(Data, 24, dstBytes, 0, 16);
                sourceIp = new IPAddress(srcBytes);
                destIp = new IPAddress(dstBytes);
            }
            else
            {
                return null;
            }
        }
        else
        {
            // For IPv4, addresses are at offsets 12 and 16
            if (Data.Length >= 20)
            {
                byte[] srcBytes = new byte[4];
                byte[] dstBytes = new byte[4];
                Array.Copy(Data, 12, srcBytes, 0, 4);
                Array.Copy(Data, 16, dstBytes, 0, 4);
                sourceIp = new IPAddress(srcBytes);
                destIp = new IPAddress(dstBytes);
            }
            else
            {
                return null;
            }
        }
        
        if (sourceIp != null && destIp != null)
        {
            return UdpPacket.FromBytes(Data, sourceIp, destIp);
        }
        
        return null;
    }
    catch
    {
        return null;
    }
}
}