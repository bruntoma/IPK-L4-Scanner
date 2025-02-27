
namespace IPK_L4_Scanner.Packet;

public class TcpHeader
{
    public int SourcePort {get;set;}
    public int DestinationPort {get;set;}

    internal void UpdateChecksum()
    {
        throw new NotImplementedException();
    }
}