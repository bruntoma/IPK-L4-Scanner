namespace IPK_L4_Scanner;

public enum PortState{
    Closed,
    Open,
    Filtered
}

public class ScanResult
{
    public int Port {get; init;}
    public PortState PortState {get; init;}

    public ScanResult(int port, PortState portState)
    {
        this.Port = port;
        this.PortState = portState;
    }
}
