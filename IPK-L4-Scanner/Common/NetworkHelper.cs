using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace IPK_L4_Scanner;

static class NetworkExtensions 
{
    public static IPAddress? GetIpOfInterface(string interfaceName, AddressFamily addressFamily, bool linkLocal)
    {
        var interfaces = NetworkInterface.GetAllNetworkInterfaces();

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
}