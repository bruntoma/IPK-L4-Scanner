using System.Net;
using System.Net.Sockets;

namespace IPK_L4_Scanner.Packets;

public abstract class IPPacket : Packet 
{

    public byte Protocol { get; init; }
    public ushort Checksum { get; init; }
    public IPAddress SourceIp { get; set; }
    public IPAddress DestinationIp { get; set; }

    public IPPacket(IPAddress source, IPAddress destination, ProtocolType protocolType, byte length) : base(length)
    {
        this.SourceIp = source;
        this.DestinationIp = destination;
    }

}