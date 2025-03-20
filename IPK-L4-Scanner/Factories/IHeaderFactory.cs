using System.Net;

public interface IHeaderFactory{
    public byte[] CreatePacket(IPEndPoint sourceEndPoint, IPEndPoint destinationEndPoint);

}