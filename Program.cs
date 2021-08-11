using System;
using System.Net;
using System.Text;
using ZeroLog;


Console.WriteLine("Hello World!");

static ResultCode FromNum(byte num)
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

static DnsRecord Read(BytePacketBuffer buffer)
{
    var log = LogManager.GetLogger("Main");
    buffer.ReadQname(out var domain);

    var qtype_num = buffer.ReadU16();
    var qtype = (QueryType)qtype_num;
    var _ = buffer.ReadU16();
    var ttl = buffer.ReadU32();
    var data_len = buffer.ReadU16();

    switch (qtype)
    {
        case QueryType.A:
        {
            var raw_addr = buffer.ReadU32();
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
            buffer.Step((byte) data_len);
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
//TODO: use System.IO.BinaryReader
public struct BytePacketBuffer
{
    public static BytePacketBuffer New()
    {
        return new BytePacketBuffer
        {
            Buf = new byte[512],
            Pos = 0
        };
    }

    public byte[] Buf { get; private set; }
    public byte Pos { get; private set; }

    public void Step(byte steps)
    {
        this.Pos += steps;
    }

    public void Seek(byte newPos)
    {
        this.Pos = newPos;
    }
    public byte Read()
    {
        if (this.Pos >= 512)
        {
            throw new Exception("End of buffer");
        }

        var res = this.Buf[this.Pos];
        this.Pos += 1;
        return res;
    }
    
    public byte Get(byte getPos)
    {
        if (getPos >= 512)
        {
            throw new Exception("End of buffer");
        }
        return this.Buf[getPos];
    }

    public Span<byte> GetRange(byte start, byte len)
    {
        if (start + len >= 512)
        {
            throw new Exception("End of buffer");
        }

        return this.Buf.AsSpan().Slice(start, len);
    }

    public ushort ReadU16()
    {
        var span = new ReadOnlySpan<byte>(this.Buf,2, this.Pos);
        this.Step(0x02);
        return BitConverter.ToUInt16(span);
    }

    public uint ReadU32()
    {
        var span = new ReadOnlySpan<byte>(this.Buf,4, this.Pos);
        this.Step(0x04);
        return BitConverter.ToUInt32(span);
    }

    /// Read a qname
    ///
    /// The tricky part: Reading domain names, taking labels into consideration.
    /// Will take something like [3]www[6]google[3]com[0] and append
    /// www.google.com to outstr.
    public void ReadQname(out string outString)
    {
        // Since we might encounter jumps, we'll keep track of our position
        // locally as opposed to using the position within the struct. This
        // allows us to move the shared position to a point past our current
        // qname, while keeping track of our progress on the current qname
        // using this variable.
        var pos = this.Pos;
        
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

            var len = this.Get(pos);
            // If len has the two most significant bit are set, it represents a
            // jump to some other offset in the packet:
            if ((len & 0xC0) == 0xC0)
            {
                if (!jumped)
                {
                    this.Seek((byte) (pos + 2));
                }
                // Read another byte, calculate offset and perform the jump by
                // updating our local position variable
                var b2 = this.Get((byte) (pos + 1));
                var offset = ((len ^ 0xC0) << 0x08) | b2;
                pos = (byte) offset;
                
                
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
                var strBuffer = this.GetRange(pos, len);
                builder.Append(Encoding.UTF8.GetString(strBuffer).ToLower());
                
                delim = ".";
                
                // Move forward the full length of the label.
                pos += len;
            }

        }

        if (!jumped)
        {
            this.Seek(pos);
        }

        outString = builder.ToString();
    }
    
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

    public void Read(BytePacketBuffer buffer)
    {
        Id = buffer.ReadU16();

        var flags = buffer.ReadU16();
        var a = (byte)(flags >> 8);
        var b = (byte)(flags & 0xFF);

        RecursionDesired = (a & (1 << 0)) > 0;
        TruncatedMessage = (a & (1 << 1)) > 0;
        AuthoritativeAnswer = (a & (1 << 2)) > 0;
        Opcode = (byte) ((a >> 3) & 0x0F);
        Response = (a & (1 << 7)) > 0;

        ResCode = (ResultCode)(b & 0x0F);
        CheckingDisabled = (b & (1 << 4)) > 0;
        AuthedData = (b & (1 << 5)) > 0;
        Z = (b & (1 << 6)) > 0;
        RecursionAvailable = (b & (1 << 7)) > 0;

        Questions = buffer.ReadU16();
        Answers = buffer.ReadU16();
        AuthoritativeEntries = buffer.ReadU16();
        ResourceEntries = buffer.ReadU16();
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

    public void Read(BytePacketBuffer buffer)
    {
        buffer.ReadQname(out var name);
        Name = name;
        QType = (QueryType)buffer.ReadU16();
        var _ = buffer.ReadU16();
    }
}

public abstract class DnsRecord
{
    public string Domain { get; set; }
    public uint Ttl { get; set; }
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

