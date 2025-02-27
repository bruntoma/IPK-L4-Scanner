using System;
using System.IO;
using System.Net;
using System.Net.Sockets;

namespace IPK_L4_Scanner.Packet;

public class TcpHeader
{
    public IpHeader ipHeader;
    public ushort SourcePort { get; set; }
    public ushort DestinationPort { get; set; }
    public uint SequenceNumber { get; set; }
    public uint AcknowledgmentNumber { get; set; }
    public byte DataOffset { get; set; }  // 4 bits, header length in 32-bit words
    public byte Flags { get; set; }        // 6 bits reserved + 6 flags
    public ushort WindowSize { get; set; }
    public ushort Checksum { get; set; }
    public ushort UrgentPointer { get; set; }
    public byte[] Options { get; set; } = Array.Empty<byte>();

    public TcpHeader(IpHeader ipHeader, ushort sourcePort, ushort destinationPort)
    {
        this.ipHeader = ipHeader;
        this.SourcePort = sourcePort;
        this.DestinationPort = destinationPort;
        this.SequenceNumber = 0;
        this.AcknowledgmentNumber = 0;
        this.DataOffset = 5;  // Default header length (5 * 4 = 20 bytes)
        this.Flags = 0;
        this.WindowSize = 64240;  // Typical default window size
        this.UrgentPointer = 0;
    }

    internal void UpdateChecksum(byte[] payload = null)
    {
        // Serialize TCP header with 0 checksum
        byte[] tcpHeaderBytes;
        using (var ms = new MemoryStream())
        using (var writer = new BinaryWriter(ms))
        {
            writer.Write(IPAddress.HostToNetworkOrder((short)SourcePort));
            writer.Write(IPAddress.HostToNetworkOrder((short)DestinationPort));
            writer.Write(IPAddress.HostToNetworkOrder((int)SequenceNumber));
            writer.Write(IPAddress.HostToNetworkOrder((int)AcknowledgmentNumber));
            
            // Combine DataOffset (4 bits) and Reserved (4 bits) + Flags (8 bits)
            ushort offsetReservedFlags = (ushort)((DataOffset << 12) | (Flags << 8));
            writer.Write(IPAddress.HostToNetworkOrder((short)offsetReservedFlags));
            
            writer.Write(IPAddress.HostToNetworkOrder((short)WindowSize));
            writer.Write((ushort)0);  // Temporary 0 checksum
            writer.Write(IPAddress.HostToNetworkOrder((short)UrgentPointer));
            
            if (Options.Length > 0)
                writer.Write(Options);

            tcpHeaderBytes = ms.ToArray();
        }

        // Get pseudo-header and combine with TCP header + payload
        var pseudoHeader = ipHeader.GetPseudoHeader(ipHeader.HeaderLength);
        var segmentLength = tcpHeaderBytes.Length + (payload?.Length ?? 0);
        
        using (var ms = new MemoryStream())
        using (var writer = new BinaryWriter(ms))
        {
            writer.Write(pseudoHeader);
            writer.Write(tcpHeaderBytes);
            if (payload != null)
                writer.Write(payload);
            
            Checksum = ComputeChecksum(ms.ToArray());
        }
    }

    public void SetFlag(TcpFlags flag)
    {
        Flags |= (byte)flag;
    }

    private static ushort ComputeChecksum(byte[] data)
    {
        uint sum = 0;
        int length = data.Length;

        for (int i = 0; i < length; i += 2)
        {
            if (i + 1 < length)
                sum += (ushort)IPAddress.NetworkToHostOrder(BitConverter.ToInt16(data, i));
            else
                sum += data[i];  // Pad with zero for odd-length data
        }

        while ((sum >> 16) != 0)
            sum = (sum & 0xFFFF) + (sum >> 16);

        return (ushort)~sum;
    }
}

public enum TcpFlags
{
    FIN = 0x01,
    SYN = 0x02,
    RST = 0x04,
    PSH = 0x08,
    ACK = 0x10,
    URG = 0x20
}