using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Text;
using ZeroLog;




var log = LogManager.GetLogger("Main");
var f = File.OpenRead("resp_google.bin");


var packet = DnsPacket.FromStream(f);

log.InfoFormat("Header - {}", packet.Header);

foreach (var q in packet.Questions)
{
    log.InfoFormat("Question - {}", q);
}

foreach (var a in packet.Answers)
{
    log.InfoFormat("Answer - {}", a);
}
foreach (var a in packet.Authorities)
{
    log.InfoFormat("Authority - {}", a);
}
foreach (var r in packet.Resources)
{
    log.InfoFormat("Resource - {}", r);
}
public enum ResultCode
{
    NOERROR = 0,
    FORMERR = 1,
    SERVFAIL = 2,
    NXDOMAIN = 3,
    NOTIMP = 4,
    REFUSED = 5,
}


public struct DnsHeader
{
    public ushort Id { get; private set; } // 16 bits
    
    public bool RecursionDesired { get; private set; } // 1 bit
    public bool TruncatedMessage { get; private set; } // 1 bit
    public bool AuthoritativeAnswer { get; private set; } // 1 bit
    public byte Opcode { get; private set; } // 4 bits
    public bool Response { get; private set; } // 1 bit
    
    public ResultCode ResCode { get; private set; } // 4 bits
    public bool CheckingDisabled { get; private set; } // 1 bit
    public bool AuthedData { get; private set; } // 1 bit
    public bool Z { get; private set; } // 1 bit
    public bool RecursionAvailable { get; private set; } // 1 bit
    
    public ushort Questions { get; private set; } // 16 bits
    public ushort Answers { get; private set; } // 16 bits
    public ushort AuthoritativeEntries { get; private set; } // 16 bits
    public ushort ResourceEntries { get; private set; } // 16 bits
    
    
    public static ResultCode GetResultCodeFromNum(byte num)
    {
        return num switch
        {
            1 => ResultCode.FORMERR,
            2 => ResultCode.SERVFAIL,
            3 => ResultCode.NXDOMAIN,
            4 => ResultCode.NOTIMP,
            5 => ResultCode.REFUSED,
            _ => ResultCode.NOERROR
        };
    }
    public static DnsHeader New()
    {
        return new DnsHeader()
        {
            Id = 0,
            RecursionDesired = false,
            TruncatedMessage = false,
            AuthoritativeAnswer = false,
            Opcode = 0,
            Response = false,
            
            ResCode = ResultCode.NOERROR,
            CheckingDisabled = false,
            AuthedData = false,
            Z = false,
            RecursionAvailable = false,
            
            Questions = 0,
            Answers = 0,
            AuthoritativeEntries = 0,
            ResourceEntries = 0
        };
    }

    public void Read(BinaryReader reader)
    {
        Id = reader.ReadUInt16();
        var flags = reader.ReadUInt16();
        var a = (byte)(flags >> 8);
        var b = (byte)(flags & 0xFF);

        RecursionDesired = (a & (1 << 0)) > 0;
        TruncatedMessage = (a & (1 << 1)) > 0;
        AuthoritativeAnswer = (a & (1 << 2)) > 0;
        Opcode = (byte) ((a >> 3) & 0x0F);
        Response = (a & (1 << 7)) > 0;

        ResCode = GetResultCodeFromNum((byte)(b & 0x0F));
        CheckingDisabled = (b & (1 << 4)) > 0;
        AuthedData = (b & (1 << 5)) > 0;
        Z = (b & (1 << 6)) > 0;
        RecursionAvailable = (b & (1 << 7)) > 0;

        Questions = reader.ReadUInt16();
        Answers = reader.ReadUInt16();
        AuthoritativeEntries = reader.ReadUInt16();
        ResourceEntries = reader.ReadUInt16();
    }
}

public enum QueryType
{
    Unknown = 0,
    A = 1
}

public struct DnsQuestion
{
    public string Name { get; private set; }
    public QueryType QType { get; private set; }

    /// Read a qname
    ///
    /// The tricky part: Reading domain names, taking labels into consideration.
    /// Will take something like [3]www[6]google[3]com[0] and append
    /// www.google.com to outstr.
    public static void ReadQname(BinaryReader reader,out string outString)
    {
        // Since we might encounter jumps, we'll keep track of our position
        // locally as opposed to using the position within the struct. This
        // allows us to move the shared position to a point past our current
        // qname, while keeping track of our progress on the current qname
        // using this variable.
        var pos = reader.BaseStream.Position;
        
        // track whether or not we've jumped
        var jumped = false;
        const int maxJumps = 5;
        var jumpsPerformed = 0;
        
        // Our delimiter which we append for each label. Since we don't want a
        // dot at the beginning of the domain name we'll leave it empty for now
        // and set it to "." at the end of the first iteration.
        var delim = "";

        var builder = new StringBuilder();

        while (true)
        {
            // Dns Packets are untrusted data, so we need to be paranoid. Someone
            // can craft a packet with a cycle in the jump instructions. This guards
            // against such packets.
            if (jumpsPerformed > maxJumps)
            {
                outString = null;
                throw new Exception($"Limit of {maxJumps} exceeded");
            }
            
            // At this point, we're always at the beginning of a label. Recall
            // that labels start with a length byte.

            Console.WriteLine($"Getting length at {pos}");
            var len = reader.ReadByte();
            Console.WriteLine($"Length is {len}");
            // If len has the two most significant bit are set, it represents a
            // jump to some other offset in the packet:
            if ((len & 0xC0) == 0xC0)
            {
                if (!jumped)
                {
                    reader.BaseStream.Seek(2, SeekOrigin.Current);
                }
                // Read another byte, calculate offset and perform the jump by
                // updating our local position variable
                var b2 = (ushort) reader.PeekChar();
                var offset = ((len ^ 0xC0) << 0x08) | b2;
                pos = (byte) offset;
                reader.BaseStream.Seek(offset, SeekOrigin.Current);
                
                
                // Indicate that a jump was performed.
                jumped = true;
                jumpsPerformed += 1;
                
                continue;
            }
            // The base scenario, where we're reading a single label and
            // appending it to the output:
            else
            {
                // Move a single byte forward to move past the length byte.
                Console.WriteLine($"Advancing pos {pos} += 1");
                pos += 1;
                
                // Domain names are terminated by an empty label of length 0,
                // so if the length is zero we're done.
                if (len == 0) {
                    Console.WriteLine($"Reached null terminator");
                    break;
                }

                // Append the delimiter to our output buffer first.
                builder.Append(delim.AsSpan());

                // Extract the actual ASCII bytes for this label and append them
                // to the output buffer.
                var strBuffer = reader.ReadChars(len);
                builder.Append(new string(strBuffer).ToLower());
                
                delim = ".";
                
                // Move forward the full length of the label.
                Console.WriteLine($"Advancing pos {pos} to {pos + len}");
                pos += len;
            }

        }

        if (!jumped)
        {
            Console.WriteLine($"Didn't jump, pos - {pos}, stream.Position - {reader.BaseStream.Position}");
            // this.Seek(pos);
        }

        outString = builder.ToString();
    }
    public void Read(BinaryReader reader)
    {
        ReadQname(reader,out var name);
        Name = name;
        QType = (QueryType)reader.ReadUInt16();
        var _ = reader.ReadUInt16();
    }
}

public abstract class DnsRecord
{
    public string Domain { get; set; }
    public uint Ttl { get; set; }
    public static DnsRecord DnsRecordRead(BinaryReader reader)
    {
        var log = LogManager.GetLogger("DnsRecord");
        DnsQuestion.ReadQname(reader,out var domain);

        var qtype_num = reader.ReadUInt16();
        var qtype = (QueryType)qtype_num;
        var _ = reader.ReadUInt16();
        var ttl = reader.ReadUInt32();
        var data_len = reader.ReadUInt16();

        switch (qtype)
        {
            case QueryType.A:
            {
                var raw_addr = reader.ReadUInt32();
                var addr = new IPAddress(raw_addr);
                log.DebugFormat("Got ip address {}", addr);
                return new DnsRecordA
                {
                    Domain = domain,
                    Address = addr,
                    Ttl = ttl
                };
            }
            case QueryType.Unknown:
                reader.BaseStream.Seek(data_len, SeekOrigin.Current);
                return new DnsRecordUnknown
                {
                    Domain = domain,
                    QType = qtype_num,
                    DataLen = data_len,
                    Ttl = ttl
                };
            default:
                throw new ArgumentOutOfRangeException();
        }
    }
}

public class DnsRecordUnknown: DnsRecord
{
    public ushort QType { get; set; }
    public ushort DataLen { get; set; }
}

public class DnsRecordA: DnsRecord
{
    public IPAddress Address { get; set; }
}

public struct DnsPacket
{
    public DnsHeader Header;
    public List<DnsQuestion> Questions;
    public List<DnsRecord> Answers;
    public List<DnsRecord> Authorities;
    public List<DnsRecord> Resources;

    public DnsPacket(List<DnsRecord> answers, List<DnsRecord> authorities, List<DnsRecord> resources, List<DnsQuestion> questions)
    {
        Answers = answers;
        Authorities = authorities;
        Resources = resources;
        Questions = questions;
        Header = DnsHeader.New();
    }

    public static DnsPacket FromStream(Stream stream)
    {
        var result = new DnsPacket(new List<DnsRecord>(),new List<DnsRecord>(), new List<DnsRecord>(), new List<DnsQuestion>());
        
        using (var reader = new BinaryReader(stream))
        {
            result.Header.Read(reader);

            for (ushort i = 0; i < result.Header.Questions; i++)
            {
                var question = new DnsQuestion();
                question.Read(reader);
                result.Questions.Add(question);
            }

            for (ushort i = 0; i < result.Header.Answers; i++)
            {
                var rec = DnsRecord.DnsRecordRead(reader);
                result.Answers.Add(rec);
            }
        
            for (ushort i = 0; i < result.Header.AuthoritativeEntries; i++)
            {
                var rec = DnsRecord.DnsRecordRead(reader);
                result.Authorities.Add(rec);
            }
            for (ushort i = 0; i < result.Header.ResourceEntries; i++)
            {
                var rec = DnsRecord.DnsRecordRead(reader);
                result.Resources.Add(rec);
            }
        }

        return result;
    }
}