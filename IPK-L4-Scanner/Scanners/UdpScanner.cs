// private TcpPacket? GetTcpPacket(byte[] responseBytes, IPEndPoint destinationEndPoint)
//     {
//         try
//         {
//             TcpPacket? tcpHeader;
//             if (scannerType == ScannerProtocol.TCP)
//             {
//                 IPPacket? ipHeader;
//                 if (destinationEndPoint.Address.AddressFamily == AddressFamily.InterNetwork)
//                 {
//                     ipHeader = IPv4Packet.FromBytes(responseBytes);
//                     if (ipHeader == null || ipHeader.SourceIp == null || ipHeader.DestinationIp == null) return null;

//                     // Verify response is from the target IP
//                     if (!ipHeader.SourceIp.Equals(destinationEndPoint.Address)) return null;

//                     tcpHeader = TcpPacket.FromBytes(responseBytes, ipHeader.SourceIp, ipHeader.DestinationIp);

//                 } 
//                 else
//                 {
//                     tcpHeader = TcpPacket.FromBytes(responseBytes, this.sourceEndPoint.Address, this.destinationIp);
//                 }
           

//                 if (tcpHeader == null) 
//                     return null;
            

//                 if (tcpHeader.DestinationPort != SOURCE_PORT)
//                     return null;

//                 if (tcpHeader.SourcePort != lastScannedPort)
//                     return null;

//                 return tcpHeader;
//             }
//             else if (scannerType == ScannerProtocol.UDP)
//             {
//                 throw new NotImplementedException("UDP not implemented");
//             }

//             return null;
//         }
//         catch
//         {
//             throw;
//         }
//     }