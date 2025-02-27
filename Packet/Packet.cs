
namespace IPK_L4_Scanner.Packet;

public class Packet
{

    private IpHeader ipHeader;
    private TcpHeader tcpHeader;

    public Packet()
    {

    }

    public void UpdateChecksums()
    {
        ipHeader.UpdateChecksum();
        tcpHeader.UpdateChecksum();
    }

}

