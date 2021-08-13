using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Text;
using Be.IO;

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
        public ushort Id { get; set; } // 16 bits

        public bool RecursionDesired { get; set; } // 1 bit
        public bool TruncatedMessage { get; set; } // 1 bit
        public bool AuthoritativeAnswer { get; set; } // 1 bit
        public byte Opcode { get; set; } // 4 bits
        public bool Response { get; set; } // 1 bit

        public ResultCode ResCode { get; set; } // 4 bits
        public bool CheckingDisabled { get; set; } // 1 bit
        public bool AuthedData { get; set; } // 1 bit
        public bool Z { get; set; } // 1 bit
        public bool RecursionAvailable { get; set; } // 1 bit

        public ushort Questions { get; set; } // 16 bits
        public ushort Answers { get; set; } // 16 bits
        public ushort AuthoritativeEntries { get; set; } // 16 bits
        public ushort ResourceEntries { get; set; } // 16 bits

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


        public void Read(BeBinaryReader reader)
        {
            Id = reader.ReadUInt16();
            var flags = reader.ReadUInt16();
            var a = (byte)(flags >> 8);
            var b = (byte)(flags & 0xFF);

            RecursionDesired = (a & (1 << 0)) > 0;
            TruncatedMessage = (a & (1 << 1)) > 0;
            AuthoritativeAnswer = (a & (1 << 2)) > 0;
            Opcode = (byte)((a >> 3) & 0x0F);
            Response = (a & (1 << 7)) > 0;

            ResCode = (ResultCode)(byte)(b & 0x0F);
            CheckingDisabled = (b & (1 << 4)) > 0;
            AuthedData = (b & (1 << 5)) > 0;
            Z = (b & (1 << 6)) > 0;
            RecursionAvailable = (b & (1 << 7)) > 0;

            Questions = reader.ReadUInt16();
            Answers = reader.ReadUInt16();
            AuthoritativeEntries = reader.ReadUInt16();
            ResourceEntries = reader.ReadUInt16();
        }

        public void Write(BeBinaryWriter writer)
        {
            writer.Write(Id);
            writer.Write((byte)(
                Convert.ToByte(RecursionDesired) << 0 |
                (Convert.ToByte(TruncatedMessage) << 1) |
                (Convert.ToByte(AuthoritativeAnswer) << 2) |
                (Opcode << 3) |
                (Convert.ToByte(Response) << 7)
            ));
            writer.Write((byte)(
                (byte)ResCode |
                (Convert.ToByte(CheckingDisabled) << 4) |
                (Convert.ToByte(AuthedData) << 5) |
                (Convert.ToByte(Z) << 6) |
                (Convert.ToByte(RecursionAvailable) << 7)
            ));
            writer.Write(Questions);
            writer.Write(Answers);
            writer.Write(AuthoritativeEntries);
            writer.Write(ResourceEntries);
        }
    }

    public enum QueryType
    {
        Unknown = 0,
        A = 1,
        NS = 2,
        CNAME = 5,
        MX = 15,
        AAAA = 28
    }

    public struct DnsQuestion
    {
        public string Name { get; set; }
        public QueryType QType { get; set; }

        public override string ToString()
        {
            return $"DnsQuestion - {Name}, QType - {Enum.GetName(QType)}";
        }

        public void Write(BeBinaryWriter writer)
        {
            WriteQname(writer, Name);
            writer.Write((ushort)QType);
            writer.Write((ushort)1);
        }

        /// Read a qname
        ///
        /// The tricky part: Reading domain names, taking labels into consideration.
        /// Will take something like [3]www[6]google[3]com[0] and append
        /// www.google.com to outstr.
        public static void ReadQname(BeBinaryReader reader, out string outString)
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
                    var b2 = (ushort)reader.PeekChar();

                    if (!jumped)
                    {
                        reader.BaseStream.Seek(1, SeekOrigin.Current); // 1 because we read len byte
                        finalAfterJumpPosition = pos + 2;
                    }

                    var offset = ((len ^ 0xC0) << 8) | b2;
                    pos = (byte)offset;
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
                    if (len == 0)
                    {
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

        public static void WriteQname(BeBinaryWriter writer, string qname)
        {
            foreach (var label in qname.Split('.'))
            {
                var len = label.Length;
                if (len > 0x3f)
                {
                    throw new Exception("Single label exceeds 63 characters of length");
                }

                writer.Write(label);
            }

            writer.Write((byte)0);
        }

        public void Read(BeBinaryReader reader)
        {
            ReadQname(reader, out var name);
            Name = name;
            QType = (QueryType)reader.ReadUInt16();
            var _ = reader.ReadUInt16();
        }
    }

    public abstract class DnsRecord
    {
        public string Domain { get; set; }
        public uint Ttl { get; set; }

        public abstract long DnsRecordWrite(BeBinaryWriter writer);

        public static DnsRecord DnsRecordRead(BeBinaryReader reader)
        {
            DnsQuestion.ReadQname(reader, out var domain);

            var qtype_num = reader.ReadUInt16();
            var qtype = (QueryType)qtype_num;
            var _ = reader.ReadUInt16();
            var ttl = reader.ReadUInt32();
            var data_len = reader.ReadUInt16();

            switch (qtype)
            {
                case QueryType.A:
                {
                    return new DnsRecordA
                    {
                        Domain = domain,
                        Address = new IPAddress(reader.ReadBytes(4).AsSpan()),
                        Ttl = ttl
                    };
                }
                case QueryType.AAAA:
                    return new DnsRecordAAAA
                    {
                        Domain = domain,
                        Address = new IPAddress(reader.ReadBytes(4 * 4).AsSpan()), // ipv6 address is 16 bytes
                        Ttl = ttl
                    };
                case QueryType.NS:
                    DnsQuestion.ReadQname(reader, out var ns);
                    return new DnsRecordNS
                    {
                        Domain = domain,
                        Host = ns,
                        Ttl = ttl
                    };
                case QueryType.CNAME:
                    DnsQuestion.ReadQname(reader, out var cname);
                    return new DnsRecordCNAME
                    {
                        Domain = domain,
                        Host = cname,
                        Ttl = ttl
                    };
                case QueryType.MX:
                    var priority = reader.ReadUInt16();
                    DnsQuestion.ReadQname(reader, out var mx);
                    return new DnsRecordMX
                    {
                        Domain = domain,
                        Priority = priority,
                        Host = mx,
                        Ttl = ttl
                    };
                default:
                    reader.BaseStream.Seek(data_len, SeekOrigin.Current);
                    return new DnsRecordUnknown
                    {
                        Domain = domain,
                        QType = qtype_num,
                        DataLen = data_len,
                        Ttl = ttl
                    };
            }
        }
    }

    public class DnsRecordUnknown : DnsRecord
    {
        public ushort QType { get; set; }
        public ushort DataLen { get; set; }

        public override string ToString()
        {
            return $"Unknown - domain {Domain}, QType - {QType}, ttl - {Ttl}, DataLen - {DataLen}";
        }

        public override long DnsRecordWrite(BeBinaryWriter writer)
        {
            var startPos = writer.BaseStream.Position;
            Console.WriteLine($"Skipping record {this}");
            return writer.BaseStream.Position - startPos;
        }
    }

    public class DnsRecordA : DnsRecord
    {
        public IPAddress Address { get; set; }

        public override string ToString()
        {
            return $"A - domain {Domain}, ip - {Address}, ttl - {Ttl}";
        }

        public override long DnsRecordWrite(BeBinaryWriter writer)
        {
            var startPos = writer.BaseStream.Position;
            DnsQuestion.WriteQname(writer, Domain);

            writer.Write((ushort)QueryType.A);
            writer.Write((ushort)1);
            writer.Write(Ttl);
            writer.Write((ushort)4);

            writer.Write(Address.GetAddressBytes());
            return writer.BaseStream.Position - startPos;
        }
    }

    public class DnsRecordAAAA : DnsRecord
    {
        public IPAddress Address { get; set; }

        public override string ToString()
        {
            return $"AAAA - domain {Domain}, ip - {Address}, ttl - {Ttl}";
        }

        public override long DnsRecordWrite(BeBinaryWriter writer)
        {
            var startPos = writer.BaseStream.Position;
            DnsQuestion.WriteQname(writer, Domain);

            writer.Write((ushort)QueryType.AAAA);
            writer.Write((ushort)1);
            writer.Write(Ttl);
            writer.Write((ushort)16);
            writer.Write(Address.GetAddressBytes());
            return writer.BaseStream.Position - startPos;
        }
    }

    public class DnsRecordNS : DnsRecord
    {
        public string Host { get; set; }

        public override string ToString()
        {
            return $"NS - domain {Domain}, host - {Host}, ttl - {Ttl}";
        }

        public override long DnsRecordWrite(BeBinaryWriter writer)
        {
            var startPos = writer.BaseStream.Position;
            DnsQuestion.WriteQname(writer, Domain);

            writer.Write((ushort)QueryType.NS);
            writer.Write((ushort)1);
            writer.Write(Ttl);

            // var pos = writer.BaseStream.Position;
            writer.Write((ushort)Host.Length * sizeof(char));

            DnsQuestion.WriteQname(writer, Host);

            // var size = writer.BaseStream.Position - (pos + 2);
            // writer.BaseStream.
            // writer.Write((ushort)16);
            // writer.Write(Address.GetAddressBytes());
            return writer.BaseStream.Position - startPos;
        }
    }

    public class DnsRecordCNAME : DnsRecord
    {
        public string Host { get; set; }

        public override string ToString()
        {
            return $"CNAME - domain {Domain}, host - {Host}, ttl - {Ttl}";
        }

        public override long DnsRecordWrite(BeBinaryWriter writer)
        {
            var startPos = writer.BaseStream.Position;
            DnsQuestion.WriteQname(writer, Domain);

            writer.Write((ushort)QueryType.CNAME);
            writer.Write((ushort)1);
            writer.Write(Ttl);

            writer.Write((ushort)Host.Length * sizeof(char));

            DnsQuestion.WriteQname(writer, Host);

            return writer.BaseStream.Position - startPos;
        }
    }

    public class DnsRecordMX : DnsRecord
    {
        public ushort Priority { get; set; }
        public string Host { get; set; }

        public override string ToString()
        {
            return $"NS - domain {Domain}, host - {Host}, Priority - {Priority}, ttl - {Ttl}";
        }

        public override long DnsRecordWrite(BeBinaryWriter writer)
        {
            var startPos = writer.BaseStream.Position;
            DnsQuestion.WriteQname(writer, Domain);

            writer.Write((ushort)QueryType.MX);
            writer.Write((ushort)1);
            writer.Write(Ttl);

            writer.Write((ushort)Host.Length * sizeof(char));
            writer.Write(Priority);

            DnsQuestion.WriteQname(writer, Host);

            return writer.BaseStream.Position - startPos;
        }
    }

    public struct DnsPacket
    {
        public DnsHeader Header;
        public List<DnsQuestion> Questions;
        public List<DnsRecord> Answers;
        public List<DnsRecord> Authorities;
        public List<DnsRecord> Resources;

        public DnsPacket(DnsHeader header)
        {
            Header = header;
            Questions = new List<DnsQuestion>(header.Questions);
            Answers = new List<DnsRecord>(header.Answers);
            Authorities = new List<DnsRecord>(header.AuthoritativeEntries);
            Resources = new List<DnsRecord>(header.ResourceEntries);
        }

        public void Log(ZeroLog.ILog log)
        {
            log.InfoFormat("Header - {0}", Header.ToString());

            foreach (var q in Questions)
            {
                log.InfoFormat("Question - {0}", q.ToString());
            }

            foreach (var a in Answers)
            {
                log.InfoFormat("Answer - {0}", a.ToString());
            }

            foreach (var a in Authorities)
            {
                log.InfoFormat("Authority - {0}", a.ToString());
            }

            foreach (var r in Resources)
            {
                log.InfoFormat("Resource - {0}", r.ToString());
            }
        }

        private void ToWriter(BeBinaryWriter writer)
        {
            Header.Questions = (ushort)Questions.Count;
            Header.Answers = (ushort)Answers.Count;
            Header.AuthoritativeEntries = (ushort)Authorities.Count;
            Header.ResourceEntries = (ushort)Resources.Count;
            Header.Write(writer);

            foreach (var q in Questions)
            {
                q.Write(writer);
            }

            foreach (var a in Answers)
            {
                a.DnsRecordWrite(writer);
            }

            foreach (var a in Authorities)
            {
                a.DnsRecordWrite(writer);
            }

            foreach (var r in Resources)
            {
                r.DnsRecordWrite(writer);
            }
        }

        public void ToStream(Stream stream, Encoding encoding = null, bool leaveOpen = false)
        {
            using (var writer = new BeBinaryWriter(stream, encoding ?? Encoding.UTF8, leaveOpen))
            {
                ToWriter(writer);
            }
        }

        private static DnsPacket FromReader(BeBinaryReader reader)
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

        public static DnsPacket FromStream(Stream stream, Encoding encoding = null, bool leaveOpen = false)
        {
            using (var reader = new BeBinaryReader(stream, encoding ?? Encoding.UTF8, leaveOpen))
            {
                return FromReader(reader);
            }
        }
    }
}