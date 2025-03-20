using System.Net;

public interface IPacketFactory{
    public byte[] CreatePacket(IPEndPoint sourceEndPoint, IPEndPoint destinationEndPoint);
}