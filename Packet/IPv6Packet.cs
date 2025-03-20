using System;
using System.Net;
using System.Net.Sockets;

namespace IPK_L4_Scanner.Packet
{
    public class IPv6Packet : IPPacket
    {

        //TODO: FIX comments
        public IPv6Packet(IPAddress source, IPAddress destination, ProtocolType protocolType) 
            : base(source, destination, protocolType)
        {
            this.Bytes = new byte[DEFAULT_IPv6_Length];
            
            // 4 bits version and 4 bits of Traffic Class.
            this.Bytes[0] = 0x60; 
            
            // Traffic Class
            this.Bytes[1] = 0x00;
            
            // Flow Label —  0.
            this.Bytes[2] = 0x00;
            this.Bytes[3] = 0x00;
            
            // Payload Length 20
            this.Bytes[4] = 0x00;
            this.Bytes[5] = 0x14;
            
            this.Bytes[6] = (byte)protocolType;
            
            this.Bytes[7] = 64;
            
            byte[] srcBytes = source.GetAddressBytes();
            if (srcBytes.Length != 16)
                throw new ArgumentException("Source address must be IPv6.");
            Array.Copy(srcBytes, 0, this.Bytes, 8, 16);
            
            byte[] dstBytes = destination.GetAddressBytes();
            if (dstBytes.Length != 16)
                throw new ArgumentException("Destination address must be IPv6.");
            Array.Copy(dstBytes, 0, this.Bytes, 24, 16);
            
        }

        public static IPv6Packet? FromBytes(byte[] packet)
        {
            if (packet.Length < 40)
                return null;
            
            int version = packet[0] >> 4;
            if (version != 6)
                return null;
            
            ProtocolType protocolType = (ProtocolType)packet[6];
            
            byte[] srcBytes = new byte[16];
            Array.Copy(packet, 8, srcBytes, 0, 16);
            IPAddress source = new IPAddress(srcBytes);
            
            byte[] dstBytes = new byte[16];
            Array.Copy(packet, 24, dstBytes, 0, 16);
            IPAddress destination = new IPAddress(dstBytes);
            
            return new IPv6Packet(source, destination, protocolType);
        }
    }
}
