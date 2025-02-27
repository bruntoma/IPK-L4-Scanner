namespace IPK_L4_Scanner;

enum PortState{
    Closed,
    Open,
    Filtered
}

class ScanResult
{
    public int Port {get; init;}
    public PortState PortState {get; init;}

    public ScanResult(int port, PortState portState)
    {
        this.Port = port;
        this.PortState = portState;
    }
}
