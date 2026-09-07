using System.Net;

namespace AntiGrabber.Service.Network;

public readonly record struct TcpFlowKey(IPAddress SrcAddr, ushort SrcPort, IPAddress DstAddr, ushort DstPort);
