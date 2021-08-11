using System;
using System.Text;
using ZeroLog;

var log = LogManager.GetLogger("Main");




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
public struct BytePacketBuffer
{
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

enum ResultCode
{
    NOERROR = 0,
    FORMERR = 1,
    SERVFAIL = 2,
    NXDOMAIN = 3,
    NOTIMP = 4,
    REFUSED = 5,
}

