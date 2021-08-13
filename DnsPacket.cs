using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Text;

namespace DnsServer
{
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

    public override string ToString()
    {
        return $"\n" +
               $"DnsHeader - id:{Id}\n" +
               $"RecursionDesired:{RecursionDesired}\n" +
               $"TruncatedMessage:{TruncatedMessage}\n" +
               $"AuthoritativeAnswer:{AuthoritativeAnswer}\n" +
               $"OpCode:{Opcode}\n" +
               $"Response:{Response}\n" +
               $"ResCode:{ResCode}\n" +
               $"CheckingDisabled:{CheckingDisabled}\n" +
               $"AuthedData:{AuthedData}\n" +
               $"Z:{Z}\n" +
               $"RecursionAvailable:{RecursionAvailable}\n" +
               $"Questions:{Questions}\n" +
               $"Answers:{Answers}\n" +
               $"AuthoritativeEntries:{AuthoritativeEntries}\n" +
               $"ResourceEntries:{ResourceEntries}";

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
        Id = reader.ReadUInt16BE();
        var flags = reader.ReadUInt16BE();
        var a = (byte)(flags >> 8);
        var b = (byte)(flags & 0xFF);

        RecursionDesired = (a & (1 << 0)) > 0;
        TruncatedMessage = (a & (1 << 1)) > 0;
        AuthoritativeAnswer = (a & (1 << 2)) > 0;
        Opcode = (byte) ((a >> 3) & 0x0F);
        Response = (a & (1 << 7)) > 0;

        ResCode = (ResultCode)(byte)(b & 0x0F);
        CheckingDisabled = (b & (1 << 4)) > 0;
        AuthedData = (b & (1 << 5)) > 0;
        Z = (b & (1 << 6)) > 0;
        RecursionAvailable = (b & (1 << 7)) > 0;

        Questions = reader.ReadUInt16BE();
        Answers = reader.ReadUInt16BE();
        AuthoritativeEntries = reader.ReadUInt16BE();
        ResourceEntries = reader.ReadUInt16BE();
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
    public override string ToString()
    {
        return $"DnsQuestion - {Name}, QType - {Enum.GetName(QType)}";
    }

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

        long finalAfterJumpPosition = 0;
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

            var len = reader.ReadByte();
            // If len has the two most significant bit are set, it represents a
            // jump to some other offset in the packet:
            if ((len & 0xC0) == 0xC0)
            {
                // Read another byte, calculate offset and perform the jump by
                // updating our local position variable
                var b2 = (ushort) reader.PeekChar();
                
                if (!jumped)
                {
                    reader.BaseStream.Seek(1, SeekOrigin.Current); // 1 because we read len byte
                    finalAfterJumpPosition = pos + 2;
                }
                
                var offset = ((len ^ 0xC0) << 8) | b2;
                pos = (byte) offset;
                reader.BaseStream.Seek(offset, SeekOrigin.Begin);
                
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
                pos += 1;
                
                // Domain names are terminated by an empty label of length 0,
                // so if the length is zero we're done.
                if (len == 0) {
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
                pos += len;
            }

        }

        if (jumped)
        {
            reader.BaseStream.Seek(finalAfterJumpPosition, SeekOrigin.Begin);
        }
        outString = builder.ToString();
    }
    public void Read(BinaryReader reader)
    {
        ReadQname(reader,out var name);
        Name = name;
        QType = (QueryType)reader.ReadUInt16BE();
        var _ = reader.ReadUInt16BE();
    }
}

public abstract class DnsRecord
{
    public string Domain { get; set; }
    public uint Ttl { get; set; }
    public static DnsRecord DnsRecordRead(BinaryReader reader)
    {
        DnsQuestion.ReadQname(reader,out var domain);

        var qtype_num = reader.ReadUInt16BE();
        var qtype = (QueryType)qtype_num;
        var _ = reader.ReadUInt16BE();
        var ttl = reader.ReadUInt32BE();
        var data_len = reader.ReadUInt16BE();

        switch (qtype)
        {
            case QueryType.A:
            {
                var raw_addr = reader.ReadUInt32BE();
                var addr = new IPAddress(raw_addr);
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
    public override string ToString()
    {
        return $"Unknown - domain {Domain}, QType - {QType}, ttl - {Ttl}, DataLen - {DataLen}";
    }
}

public class DnsRecordA: DnsRecord
{
    public IPAddress Address { get; set; }
    public override string ToString()
    {
        return $"A - domain {Domain}, ip - {Address}, ttl - {Ttl}";
    }
}

public struct DnsPacket
{
    public DnsHeader Header;
    public List<DnsQuestion> Questions;
    public List<DnsRecord> Answers;
    public List<DnsRecord> Authorities;
    public List<DnsRecord> Resources;

    private DnsPacket(DnsHeader header)
    {
        Header = header;
        Questions = new List<DnsQuestion>(header.Questions);
        Answers =  new List<DnsRecord>(header.Answers);
        Authorities = new List<DnsRecord>(header.AuthoritativeEntries);
        Resources = new List<DnsRecord>(header.ResourceEntries);
    }

    public static DnsPacket FromStream(Stream stream)
    {
        using (var reader = new BinaryReader(stream))
        {
            var header = DnsHeader.New();
            header.Read(reader);
            var result = new DnsPacket(header);
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
            return result;
        }
    }
}
}