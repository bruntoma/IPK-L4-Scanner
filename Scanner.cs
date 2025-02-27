using System.Net;
using System.Net.Sockets;
using static IPK_L4_Scanner.NetworkExtensions;

namespace IPK_L4_Scanner;

enum ScannerProtocol {
    TCP,
    UDP
}

class Scanner : IDisposable
{
    private const int SOURCE_PORT = 258;

    
    private Socket socket;
    private PacketFactory packetFactory;
    private IPAddress destinationIp;
    private ScannerProtocol scannerType;
    private string interfaceName;
    private int timeout;
    private int delayBetweenScans;

    public Scanner(string interfaceName, IPAddress destinationIp, ScannerProtocol scannerType, int timeout = 5000, int delayBetweenScans = 0)
    {
        this.socket = new Socket(destinationIp.AddressFamily, SocketType.Raw, System.Net.Sockets.ProtocolType.Raw);
        this.destinationIp = destinationIp;
        this.scannerType = scannerType;
        this.packetFactory = new PacketFactory();
        this.interfaceName = interfaceName;
        this.timeout = timeout;
        this.delayBetweenScans = delayBetweenScans;
    }

    private void PrepareSocket()
    {
        var ip = GetIpOfInterface(interfaceName, destinationIp.AddressFamily) ?? throw new Exception($"Could not find IPAddress of netowrk interface ({interfaceName})");
        this.socket.Bind(new IPEndPoint(ip, SOURCE_PORT));
    }

    public async Task<ScanResult> ScanPort(int port, bool retry = false)
    {
        var destinationEndPoint = new IPEndPoint(destinationIp, port);
        var buffer = new byte[65535];

        Task<byte[]> receiveTask = Task.Run(() => 
        {
            do {
                    socket.Receive(buffer);
            } while(!IsValidResponse(buffer));

            return buffer;
        });


        socket.SendTo(packetFactory.CreatePacket(scannerType), destinationEndPoint);

        if (await Task.WhenAny(receiveTask, Task.Delay(timeout)) == receiveTask)
        {
            if (IsValidResponse(buffer))
            {
                return GetScanResultFromResponse(buffer);
            }
        }
        
        if (retry == false)
        {
            await ScanPort(port, true);
        }
        return new ScanResult(port, PortState.Filtered);
    }

    private bool IsValidResponse(byte[] buffer)
    {
        return false;
    }

    private ScanResult GetScanResultFromResponse(byte[] reponsePacket)
    {
        return new ScanResult(0, PortState.Open);
    }

    public void Dispose()
    {
        socket.Dispose();
    }
}
