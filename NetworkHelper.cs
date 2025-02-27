using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace IPK_L4_Scanner;

static class NetworkExtensions 
{
    public static IPAddress? GetIpOfInterface(string interfaceName, AddressFamily addressFamily)
    {
        return NetworkInterface.GetAllNetworkInterfaces()
        .Where(i => i.Name == interfaceName)
        .SelectMany(i => i.GetIPProperties().UnicastAddresses)
        .Select(a => a.Address)
        .FirstOrDefault(a => a.AddressFamily == addressFamily);
    }
}