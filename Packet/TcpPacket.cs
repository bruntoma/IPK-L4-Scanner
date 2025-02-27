using System;
using System.IO;
using System.Net;
using System.Net.Sockets;

namespace IPK_L4_Scanner.Packet;

public class TcpHeader
{
    public IpHeader IpHeader {get;set;}
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

    public TcpHeader(ushort sourcePort, ushort destinationPort)
    {
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
        var pseudoHeader = IpHeader.GetPseudoHeader(IpHeader.HeaderLength);
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



  public byte[] ToBytes()
    {
        UpdateDataOffset();  // Ensure DataOffset matches options length
        
        using var ms = new MemoryStream();
        using var writer = new BinaryWriter(ms);
        
        writer.Write(IPAddress.HostToNetworkOrder((short)SourcePort));
        writer.Write(IPAddress.HostToNetworkOrder((short)DestinationPort));
        writer.Write(IPAddress.HostToNetworkOrder((int)SequenceNumber));
        writer.Write(IPAddress.HostToNetworkOrder((int)AcknowledgmentNumber));
        
        // Combine DataOffset (4 bits) and Flags (8 bits)
        ushort offsetFlags = (ushort)((DataOffset << 12) | (Flags << 8));
        writer.Write(IPAddress.HostToNetworkOrder((short)offsetFlags));
        
        writer.Write(IPAddress.HostToNetworkOrder((short)WindowSize));
        writer.Write(IPAddress.HostToNetworkOrder((short)Checksum));
        writer.Write(IPAddress.HostToNetworkOrder((short)UrgentPointer));
        
        if (Options.Length > 0)
            writer.Write(Options);

        return ms.ToArray();
    }

    public static TcpHeader FromBytes(byte[] bytes)
    {
        if (bytes.Length < 20)
            throw new ArgumentException("Invalid TCP header - too short");

        using var ms = new MemoryStream(bytes);
        using var reader = new BinaryReader(ms);
        
        var header = new TcpHeader(
            sourcePort: (ushort)IPAddress.NetworkToHostOrder(reader.ReadInt16()),
            destinationPort: (ushort)IPAddress.NetworkToHostOrder(reader.ReadInt16()))
        {
            SequenceNumber = (uint)IPAddress.NetworkToHostOrder(reader.ReadInt32()),
            AcknowledgmentNumber = (uint)IPAddress.NetworkToHostOrder(reader.ReadInt32())
        };

        // Parse DataOffset and Flags
        var offsetFlags = (ushort)IPAddress.NetworkToHostOrder(reader.ReadInt16());
        header.DataOffset = (byte)((offsetFlags >> 12) & 0x0F);
        header.Flags = (byte)((offsetFlags >> 8) & 0xFF);

        header.WindowSize = (ushort)IPAddress.NetworkToHostOrder(reader.ReadInt16());
        header.Checksum = (ushort)IPAddress.NetworkToHostOrder(reader.ReadInt16());
        header.UrgentPointer = (ushort)IPAddress.NetworkToHostOrder(reader.ReadInt16());

        // Read options if present
        var headerLength = header.DataOffset * 4;
        if (headerLength < 20)
            throw new ArgumentException("Invalid TCP header length");
        
        var optionsLength = headerLength - 20;
        if (optionsLength > 0)
        {
            header.Options = reader.ReadBytes(optionsLength);
            if (header.Options.Length != optionsLength)
                throw new ArgumentException("Incomplete TCP options");
        }

        return header;
    }

    private void UpdateDataOffset()
    {
        var headerLength = 20 + Options.Length;
        if (headerLength % 4 != 0)
            throw new InvalidOperationException("TCP header length must be multiple of 4 bytes");
        
        DataOffset = (byte)(headerLength / 4);
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
