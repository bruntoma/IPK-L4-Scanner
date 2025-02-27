using System;
using System.Net;
using System.Net.Sockets;
using System.IO;
using System.Linq;

namespace IPK_L4_Scanner.Packet;

public enum IPVersion {
    IPv4 = 4,
    IPv6 = 6
}

[Flags]
public enum IpFlags
{
    None = 0,
    DontFragment = 0x4000, // Bit 14 (DF flag)
    MoreFragments = 0x2000  // Bit 13 (MF flag)
}

public class IpHeader
{
    private const byte DEFAULT_IPv4_Length = 20;
    private const byte DEFAULT_IPv6_Length = 40;

    public byte Version { get; set; }
    public byte HeaderLength { get; set; }
    public byte TypeOfService { get; set; }
    public ushort TotalLength { get; set; }
    public ushort IdentificationNumber { get; set; }
    public ushort FragmentOffset { get; set; }
    public byte TimeToLive { get; set; }
    public byte Protocol { get; set; }
    public ushort Checksum { get; set; }
    public IPAddress SourceIp { get; set; }
    public IPAddress DestinationIp { get; set; }

    public IpHeader(IPAddress sourceIp, IPAddress destinationIp, IPVersion version = IPVersion.IPv4)
    {
        Version = (byte)version;
        HeaderLength = (version == IPVersion.IPv4) ? DEFAULT_IPv4_Length : DEFAULT_IPv6_Length;
        TypeOfService = 0;
        IdentificationNumber = 0;
        FragmentOffset = 0;
        TimeToLive = 1;
        Protocol = 0;
        SourceIp = sourceIp;
        DestinationIp = destinationIp;
        Checksum = 0;
    }

    public byte[] GetPseudoHeader(int ipHeaderLength)
    {
        if (Version == (byte)IPVersion.IPv4)
        {
            byte[] pseudoHeader = new byte[12];
            SourceIp.GetAddressBytes().CopyTo(pseudoHeader, 0);
            DestinationIp.GetAddressBytes().CopyTo(pseudoHeader, 4);
            pseudoHeader[8] = 0;
            pseudoHeader[9] = Protocol;
            ushort segmentLength = (ushort)(TotalLength - ipHeaderLength);
            byte[] lengthBytes = BitConverter.GetBytes(segmentLength);
            if (BitConverter.IsLittleEndian)
                Array.Reverse(lengthBytes);
            Buffer.BlockCopy(lengthBytes, 0, pseudoHeader, 10, 2);
            return pseudoHeader;
        }
        else
        {
            byte[] pseudoHeader = new byte[40];
            SourceIp.GetAddressBytes().CopyTo(pseudoHeader, 0);
            DestinationIp.GetAddressBytes().CopyTo(pseudoHeader, 16);
            uint payloadLength = (uint)TotalLength;
            byte[] lengthBytes = BitConverter.GetBytes(payloadLength);
            if (BitConverter.IsLittleEndian)
                Array.Reverse(lengthBytes);
            Buffer.BlockCopy(lengthBytes, 0, pseudoHeader, 32, 4);
            pseudoHeader[36] = 0;
            pseudoHeader[37] = 0;
            pseudoHeader[38] = 0;
            pseudoHeader[39] = Protocol;
            return pseudoHeader;
        }
    }

    internal void UpdateChecksum()
    {
        if (Version != (byte)IPVersion.IPv4)
            return;

        byte[] headerBytes = new byte[HeaderLength];
        using (var ms = new MemoryStream(headerBytes))
        using (var writer = new BinaryWriter(ms))
        {
            byte versionIhl = (byte)((Version << 4) | (HeaderLength / 4));
            writer.Write(versionIhl);
            writer.Write(TypeOfService);
            writer.Write(IPAddress.HostToNetworkOrder((short)TotalLength));
            writer.Write(IPAddress.HostToNetworkOrder((short)IdentificationNumber));
            writer.Write(IPAddress.HostToNetworkOrder((short)FragmentOffset));
            writer.Write(TimeToLive);
            writer.Write(Protocol);
            writer.Write((ushort)0); // Checksum initially 0
            writer.Write(SourceIp.GetAddressBytes());
            writer.Write(DestinationIp.GetAddressBytes());
        }

        Checksum = ComputeChecksum(headerBytes);
    }

    private static ushort ComputeChecksum(byte[] data)
    {
        uint sum = 0;
        for (int i = 0; i < data.Length; i += 2)
        {
            ushort word = (ushort)((data[i] << 8) + (i + 1 < data.Length ? data[i + 1] : (byte)0));
            sum += word;
        }

        while ((sum >> 16) != 0)
            sum = (sum & 0xFFFF) + (sum >> 16);

        return (ushort)~sum;
    }

      public byte[] ToBytes()
    {
        if (Version == (byte)IPVersion.IPv4)
            return GetIPv4Bytes();
        
        if (Version == (byte)IPVersion.IPv6)
            return GetIPv6Bytes();
        
        throw new NotSupportedException($"IP version {Version} not supported");
    }

    // Add to existing IpHeader class:
    public static IpHeader FromBytes(byte[] data)
    {
        byte version = (byte)(data[0] >> 4);
        if (version == (byte)IPVersion.IPv4)
        {
            return new IpHeader(
                sourceIp: new IPAddress(BitConverter.ToUInt32(data, 12)),
                destinationIp: new IPAddress(BitConverter.ToUInt32(data, 16)))
            {
                Version = version,
                HeaderLength = (byte)((data[0] & 0x0F) * 4),
                Protocol = data[9],
                TotalLength = (ushort)IPAddress.NetworkToHostOrder(BitConverter.ToInt16(data, 2))
            };
        }
        throw new NotImplementedException("IPv6 not implemented");
    }

    private byte[] GetIPv4Bytes()
    {
        byte[] header = new byte[HeaderLength];
        using (var ms = new MemoryStream(header))
        using (var writer = new BinaryWriter(ms))
        {
            // Version (4 bits) + IHL (4 bits)
            byte versionIhl = (byte)((Version << 4) | (HeaderLength / 4));
            writer.Write(versionIhl);
            
            writer.Write(TypeOfService);
            writer.Write(IPAddress.HostToNetworkOrder((short)TotalLength));
            writer.Write(IPAddress.HostToNetworkOrder((short)IdentificationNumber));
            
            // Flags (3 bits) + Fragment Offset (13 bits)
            writer.Write(IPAddress.HostToNetworkOrder((short)FragmentOffset));
            
            writer.Write(TimeToLive);
            writer.Write(Protocol);
            writer.Write(Checksum);
            writer.Write(SourceIp.GetAddressBytes());
            writer.Write(DestinationIp.GetAddressBytes());
        }
        return header;
    }

    private byte[] GetIPv6Bytes()
    {
        byte[] header = new byte[HeaderLength];
        using (var ms = new MemoryStream(header))
        using (var writer = new BinaryWriter(ms))
        {
            // Version (4 bits) | Traffic Class (8 bits) | Flow Label (20 bits)
            uint versionClassFlow = (uint)(Version << 28) | (uint)(TypeOfService << 20);
            writer.Write(IPAddress.HostToNetworkOrder((int)versionClassFlow));
            
            // Payload Length (TCP/UDP header + data)
            writer.Write(IPAddress.HostToNetworkOrder((ushort)(TotalLength - HeaderLength)));
            writer.Write(Protocol);  // Next Header
            writer.Write(TimeToLive); // Hop Limit
            writer.Write(SourceIp.GetAddressBytes());
            writer.Write(DestinationIp.GetAddressBytes());
        }
        return header;
    }
}