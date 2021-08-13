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
        static async Task Main(string[] args)
        {
            BasicConfigurator.Configure(new[] { new ConsoleAppender() });
            var log = LogManager.GetLogger("Main");

            var qName = "yahoo.com";
            var qType = QueryType.MX;

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
            udpClient.Connect("8.8.8.8", 53);
            var ms = new MemoryStream();
            var watch = new Stopwatch();
            watch.Start();
            packet.ToStream(ms, leaveOpen: true);
            watch.Stop();

            log.InfoFormat("Wrote packet to stream in {0} ms", watch.ElapsedMilliseconds.ToString());
            ms.Seek(0, SeekOrigin.Begin);
            log.Info(BitConverter.ToString(ms.ToArray()).Replace("-", ""));

            ms.Seek(0, SeekOrigin.Begin);
            watch.Start();
            var sanityCheckPacket = DnsPacket.FromStream(ms, leaveOpen: true);
            watch.Stop();
            log.InfoFormat("Read sanity packet from stream in {0} ms", watch.ElapsedMilliseconds.ToString());

            sanityCheckPacket.Log(log);
            ms.Seek(0, SeekOrigin.Begin);
            var respCode = await udpClient.SendAsync(ms.ToArray());
            log.InfoFormat("Received response {0} from udp server", respCode.ToString());

            var RemoteIpEndPoint = new IPEndPoint(IPAddress.Any, 0);
            var response = new MemoryStream(udpClient.Receive(ref RemoteIpEndPoint));

            log.Info(BitConverter.ToString(response.ToArray()).Replace("-", ""));
            watch.Start();
            var resPacket = DnsPacket.FromStream(response);
            watch.Stop();
            log.InfoFormat("Read resp packet from stream in {0} ms", watch.ElapsedMilliseconds.ToString());
            log.Info("Response packet:");
            resPacket.Log(log);

            LogManager.Shutdown();
        }
    }
}