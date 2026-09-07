using System.Net;

namespace AntiGrabber.Service.Network;

public readonly record struct UdpFlowKey(IPAddress SrcAddr, ushort SrcPort, IPAddress DstAddr, ushort DstPort);
