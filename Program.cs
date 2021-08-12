using System.IO;
using DnsServer;
using ZeroLog;
using ZeroLog.Appenders;
using ZeroLog.Config;


BasicConfigurator.Configure(new[] { new ConsoleAppender() });
var log = LogManager.GetLogger("Main");
var f = File.OpenRead("resp_google.bin");


var packet = DnsPacket.FromStream(f);


log.InfoFormat("Header - {0}", packet.Header.ToString());

foreach (var q in packet.Questions)
{
    log.InfoFormat("Question - {0}", q.ToString());
}

foreach (var a in packet.Answers)
{
    log.InfoFormat("Answer - {0}", a.ToString());
}
foreach (var a in packet.Authorities)
{
    log.InfoFormat("Authority - {0}", a.ToString());
}
foreach (var r in packet.Resources)
{
    log.InfoFormat("Resource - {0}", r.ToString());
}
f.Close();
LogManager.Shutdown();
