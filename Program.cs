using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using ZeroLog;
using ZeroLog.Appenders;
using ZeroLog.Config;

namespace DnsServer
{
    class Program
    {
        static async Task<DnsPacket> Lookup(ILog log, string qName, QueryType qType, IPAddress hostname, int remotePort = 53)
        {
            var udpClient = new UdpClient(Random.Shared.Next(40000,45000));
            var header = DnsHeader.New();
            header.Id = (ushort) Random.Shared.Next();
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
            log.InfoFormat("Received response {0} from udp server {1}", respCode.ToString(), hostname.ToString());
            // var RemoteIpEndPoint = new IPEndPoint(IPAddress.Any, 0);
            var received = await udpClient.ReceiveAsync();
            var response = new MemoryStream(received.Buffer.ToArray());
            
            var resPacket = DnsPacket.FromStream(response);
            log.Debug("Response packet:");
            resPacket.Log(log);
            udpClient.Close();
            return resPacket;
        }

        static async Task<DnsPacket> RecursiveLookup(ILog log, string qName, QueryType queryType)
        {
            // For now we're always starting with *a.root-servers.net*.
            var ns = IPAddress.Parse("198.41.0.4");
            // Since it might take an arbitrary number of steps, we enter an unbounded loop.
            while (true)
            {
                log.DebugFormat("attempting lookup of {0} {1} with ns {2}",Enum.GetName(queryType),qName,ns.ToString());
                // The next step is to send the query to the active server.
                var ns_copy = ns;
                var response = await Lookup(log, qName, queryType, ns_copy, 53);
                if (response.Answers.Count != 0 && response.Header.ResCode == ResultCode.NOERROR)
                {
                    return response;
                }
                // We might also get a `NXDOMAIN` reply, which is the authoritative name servers
                // way of telling us that the name doesn't exist.

                if (response.Header.ResCode == ResultCode.NXDOMAIN)
                {
                    return response;
                }
                
                // Otherwise, we'll try to find a new nameserver based on NS and a corresponding A
                // record in the additional section. If this succeeds, we can switch name server
                // and retry the loop.
                var new_ns = response.GetResolvedNS(qName);
                if (new_ns != null)
                {
                    ns = new_ns;
                    continue;
                }
                // If not, we'll have to resolve the ip of a NS record. If no NS records exist,
                // we'll go with what the last server told us.
                var new_ns_name = response.GetUnresolvedNS(qName);
                if (string.IsNullOrWhiteSpace(new_ns_name))
                {
                    return response;
                }
                // Here we go down the rabbit hole by starting _another_ lookup sequence in the
                // midst of our current one. Hopefully, this will give us the IP of an appropriate
                // name server.
                var recursive_response = await RecursiveLookup(log, new_ns_name, QueryType.A);
                
                // Finally, we pick a random ip from the result, and restart the loop. If no such
                // record is available, we again return the last result we got.
                var new_ns_2 = recursive_response.GetRandomA();
                if (new_ns_2 != null)
                {
                    ns = new_ns_2;
                }
                else
                {
                    return response;
                }
            }
        }

        static async Task HandleQuery(ILog log, UdpClient client, CancellationToken cancellationToken = default)
        {
            log.Debug("Created connection");
            var readResult = await client.ReceiveAsync(cancellationToken);
            var stream = new MemoryStream(readResult.Buffer.ToArray());
            log.Debug("Created stream");
            // Next, `DnsPacket::from_buffer` is used to parse the raw bytes into
            // a `DnsPacket`.
            var reqPacket = DnsPacket.FromStream(stream, leaveOpen:false);
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
                    var res = await RecursiveLookup(log, question.Name, question.QType);
                    respPacket.Questions.Add(question);
                    respPacket.Header.ResCode = res.Header.ResCode;
                    respPacket.Answers.AddRange(res.Answers);
                    respPacket.Authorities.AddRange(res.Authorities);
                    respPacket.Resources.AddRange(res.Resources);
                    log.Info("Finished lookup packet");
                }
                catch (Exception e)
                {
                    log.ErrorFormat("Exception in lookup - {0}",e.ToString());
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
            await client.SendAsync(ms.ToArray(),readResult.RemoteEndPoint, cancellationToken);
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
                await HandleQuery(log, client);
            }
            
            LogManager.Shutdown();
        }
    }
}