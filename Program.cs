using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;
using ZeroLog;
using ZeroLog.Appenders;
using ZeroLog.Config;

namespace DnsServer
{
    class Program
    {
        static async Task<DnsPacket> Lookup(ILog log, string qName, QueryType qType)
        {
            var udpClient = new UdpClient(43210);
            var header = DnsHeader.New();
            header.Id = 6666;
            header.Questions = 1;
            header.RecursionDesired = true;
            var question = new DnsQuestion { Name = qName, QType = qType };
            var packet = new DnsPacket(header);
            packet.Questions.Add(question);
            log.Debug("Request packet:");
            packet.Log(log);
            udpClient.Connect("8.8.8.8", 53);
            var ms = new MemoryStream();
            packet.ToStream(ms, leaveOpen: false);
            var respCode = await udpClient.SendAsync(ms.ToArray());
            log.InfoFormat("Received response {0} from udp server", respCode.ToString());
            var RemoteIpEndPoint = new IPEndPoint(IPAddress.Any, 0);
            var response = new MemoryStream(udpClient.Receive(ref RemoteIpEndPoint));
            var resPacket = DnsPacket.FromStream(response);
            log.Debug("Response packet:");
            resPacket.Log(log);
            return resPacket;
        }
        
        static async Task Main(string[] args)
        {
            BasicConfigurator.Configure(new[] { new ConsoleAppender() });
            var log = LogManager.GetLogger("Main");

            var qName = "yahoo.com";
            var qType = QueryType.MX;

            var _ = await Lookup(log, qName, qType); 

            LogManager.Shutdown();
        }
    }
}