using System;
using System.Buffers;
using System.Diagnostics;
using System.IO;
using System.IO.Pipelines;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Pipelines.Sockets.Unofficial;
using ZeroLog;
using ZeroLog.Appenders;
using ZeroLog.Config;

namespace DnsServer
{
    class Program
    {
        static async Task<DnsPacket> Lookup(ILog log, string qName, QueryType qType, string hostname = "8.8.8.8", int remotePort = 53, int localPort = 43210)
        {
            var udpClient = new UdpClient(localPort);
            var header = DnsHeader.New();
            header.Id = 6666;
            header.Questions = 1;
            header.RecursionDesired = true;
            var question = new DnsQuestion { Name = qName, QType = qType };
            var packet = new DnsPacket(header);
            packet.Questions.Add(question);
            log.Debug("Request packet:");
            packet.Log(log);
            udpClient.Connect(hostname, remotePort);
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

        static async Task HandleQuery(ILog log, Socket socket, CancellationToken cancellationToken = default)
        {
            using var connection = SocketConnection.Create(socket);
            log.Debug("Created connection");
            var readResult = await connection.Input.ReadAsync(cancellationToken);
            var stream = new MemoryStream(readResult.Buffer.ToArray());
            log.Debug("Created stream");
            // Next, `DnsPacket::from_buffer` is used to parse the raw bytes into
            // a `DnsPacket`.
            var reqPacket = DnsPacket.FromStream(stream, leaveOpen:true);
            log.Debug("Request packet:");
            reqPacket.Log(log);
            
            // Create and initialize the response packet
            var respHeader = DnsHeader.New();
            respHeader.Id = reqPacket.Header.Id;
            respHeader.RecursionDesired = true;
            respHeader.RecursionAvailable = true;
            respHeader.Response = true;
            var respPacket = new DnsPacket(respHeader);
            log.Debug("Response packet:");
            respPacket.Log(log);
            
            // In the normal case, exactly one question is present
            if (reqPacket.Questions.Count == 1)
            {
                var question = reqPacket.Questions[0];
                // Since all is set up and as expected, the query can be forwarded to the
                // target server. There's always the possibility that the query will
                // fail, in which case the `SERVFAIL` response code is set to indicate
                // as much to the client. If rather everything goes as planned, the
                // question and response records as copied into our response packet.
                try
                {
                    var res = await Lookup(log, question.Name, question.QType);
                    respPacket.Questions.Add(question);
                    respPacket.Header.ResCode = res.Header.ResCode;
                    respPacket.Answers.AddRange(res.Answers);
                    respPacket.Authorities.AddRange(res.Authorities);
                    respPacket.Resources.AddRange(res.Resources);
                    log.Info("Finished lookup packet");
                    // respPacket.ToStream(connection.Output.AsStream(), leaveOpen:true);
                }
                catch (Exception e)
                {
                    log.ErrorFormat("Exception in lookup - {0}",e);
                    respPacket.Header.ResCode = ResultCode.SERVFAIL;
                }
                
                
            }
            else
            {
                log.Debug("More than one question");
                // Being mindful of how unreliable input data from arbitrary senders can be, we
                // need make sure that a question is actually present. If not, we return `FORMERR`
                // to indicate that the sender made something wrong.
                respPacket.Header.ResCode = ResultCode.FORMERR;
            }

            log.Info("Writing response to stream");
            var ms = new MemoryStream();
            respPacket.ToStream(ms, leaveOpen: false);
            await connection.Output.WriteAsync(ms.ToArray(),cancellationToken);
            log.Info("Completed");
        }
        
        static async Task Main(string[] args)
        {
            BasicConfigurator.Configure(new[] { new ConsoleAppender() });
            var log = LogManager.GetLogger("Main");

            // var qName = "yahoo.com";
            // var qType = QueryType.MX;

            // var _ = await Lookup(log, qName, qType); 

            // var endpoint = new IPEndPoint(IPAddress.Any, 2053);
            var client = new UdpClient(2053);
            while (true)
            {
                await HandleQuery(log, client.Client);
            }
            
            LogManager.Shutdown();
        }
    }
}