namespace IPK_L4_Scanner.Packet;


public abstract class Packet {
    public byte[]? Bytes { get; protected set; }  
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