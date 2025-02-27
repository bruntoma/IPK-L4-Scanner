namespace IPK_L4_Scanner.Packet;

public class IcmpHeader
{
    public byte Type { get; set; }
    public byte Code { get; set; }
    public ushort Checksum { get; set; }
    public byte[] Payload { get; set; }

    public static IcmpHeader FromBytes(byte[] data, int offset)
    {
        return new IcmpHeader
        {
            Type = data[offset],
            Code = data[offset + 1],
            Checksum = BitConverter.ToUInt16(data, offset + 2),
            Payload = data.Skip(offset + 4).ToArray()
        };
    }

    public bool IsPortUnreachableError(int targetPort)
    {
        if (Type != 3 || Code != 3) return false; // Not "Port Unreachable"

        try
        {
            // Extract original UDP header from payload (starts after 20 bytes of original IP header)
            var udpHeaderBytes = Payload.Skip(20).Take(8).ToArray();
            var originalPort = BitConverter.ToUInt16(udpHeaderBytes, 2);
            return originalPort == targetPort;
        }
        catch
        {
            return false;
        }
    }
}