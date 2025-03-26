using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace IPK_L4_Scanner;


public class NetworkHelper {

    public static IPAddress? GetIpOfInterface(string interfaceName, AddressFamily addressFamily, bool linkLocal)
    {
        return NetworkInterface.GetAllNetworkInterfaces()
        .Where(i => i.Name == interfaceName)
        .SelectMany(i => i.GetIPProperties().UnicastAddresses)
        .Select(a => a.Address)
        .Where(addr => IsValidIp(addr, linkLocal))
        .FirstOrDefault(a => a.AddressFamily == addressFamily);
    }

    private static bool IsValidIp(IPAddress address, bool linkLocal)
    {
        if (address.AddressFamily == AddressFamily.InterNetwork) return true;

        if (address.AddressFamily == AddressFamily.InterNetworkV6)
        {
            if (linkLocal == address.IsIPv6LinkLocal)
                return true;
        }

        return false;
    }


    public static int? GetRandomAvailablePort()
    {
        Socket s = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        s.Bind(new IPEndPoint(IPAddress.Any, 0));
        var endpoint = s.LocalEndPoint as IPEndPoint;
        int? port = endpoint?.Port;
        s.Dispose();
        return port;
    }
}