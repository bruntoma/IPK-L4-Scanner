namespace IPK_L4_Scanner.Packets;


public abstract class Packet {
    public static byte DEFAULT_IPv4_Length = 20;
    public static byte DEFAULT_IPv6_Length = 40;

    public static byte DEFAULT_TCP_Length = 20;

    public static byte DEFAULT_UDP_Length = 8;

    public static byte DEFAULT_ICMP_Length = 8;


    

    public byte Length {get; init;}
    public byte[]? Bytes { get; protected set; }  

    public Packet(byte length)
    {
        this.Length = length;
    }

    public ushort CalculateChecksum(byte[] buffer, int offset, int length)
    {
        uint checksum = 0;
        for (int i = offset; i < offset + length; i += 2)
        {
            if (i + 1 < offset + length)
            {
                checksum += (ushort)((buffer[i] << 8) | buffer[i + 1]);
            }
            else
            {
                checksum += (ushort)(buffer[i] << 8);
            }
        }
        checksum = (checksum >> 16) + (checksum & 0xFFFF);
        checksum += checksum >> 16;
        return (ushort)~checksum;
    }


}