using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace IPK_L4_Scanner;


public class NetworkHelper {
    public NetworkInterface[] GetAllNetworkInterfaces() => NetworkInterface.GetAllNetworkInterfaces();   

    public IPAddress? GetIpOfInterface(string interfaceName, AddressFamily addressFamily, bool linkLocal)
    {
        var networkInterfaces = GetAllNetworkInterfaces();
        return networkInterfaces
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