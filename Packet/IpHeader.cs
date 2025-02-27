
using System.Net;

namespace IPK_L4_Scanner.Packet;

public class IpHeader
{
    public IPAddress SourceIp {get;set;}
    public IPAddress DestinationIp {get;set;}

    public IpHeader(IPAddress sourceIp, IPAddress destinationIp)
    {
        this.SourceIp = sourceIp;
        this.DestinationIp = destinationIp;
    }

    internal void UpdateChecksum()
    {
        throw new NotImplementedException();
    }
}