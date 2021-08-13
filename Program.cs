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
        static async Task Main(string[] args)
        {
            BasicConfigurator.Configure(new[] { new ConsoleAppender() });
            var log = LogManager.GetLogger("Main");

            var qName = "google.com";
            var qType = QueryType.A;

            var udpClient = new UdpClient(43210);

            var header = DnsHeader.New();
            header.Id = 6666;
            header.Questions = 1;
            header.RecursionDesired = true;
            var question = new DnsQuestion { Name = qName, QType = qType };
            var packet = new DnsPacket(header);
            packet.Questions.Add(question);

            log.Info("Request packet:");
            packet.Log(log);
            // udpClient.Connect("8.8.8.8", 53);
            var ms = new MemoryStream();
            
            packet.ToStream(ms, leaveOpen:true);

            ms.Seek(0, SeekOrigin.Begin);
            var sanityCheckPacket = DnsPacket.FromStream(ms, leaveOpen:true);
            sanityCheckPacket.Log(log);
            // var respCode = udpClient.Send(ms.ToArray());
            // log.InfoFormat("Received response {0} from udp server", respCode.ToString());
            //
            // var RemoteIpEndPoint = new IPEndPoint(IPAddress.Any, 0);
            // var response = new MemoryStream(udpClient.Receive(ref RemoteIpEndPoint));
            //
            // log.Info("Response packet:");
            // var resPacket = DnsPacket.FromStream(response);
            // resPacket.Log(log);
            
            

            LogManager.Shutdown();

        }
    }
}

