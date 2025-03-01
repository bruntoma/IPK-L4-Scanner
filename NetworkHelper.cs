using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace IPK_L4_Scanner;

static class NetworkExtensions 
{
    public static IPAddress? GetIpOfInterface(string interfaceName, AddressFamily addressFamily)
    {
        var interfaces = NetworkInterface.GetAllNetworkInterfaces();

        return NetworkInterface.GetAllNetworkInterfaces()
        .Where(i => i.Name == interfaceName)
        .SelectMany(i => i.GetIPProperties().UnicastAddresses)
        .Select(a => a.Address)
        .Where(addr => addr.IsIPv6LinkLocal)
        .FirstOrDefault(a => a.AddressFamily == addressFamily);
    }
}