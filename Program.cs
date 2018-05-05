using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Security;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;

namespace InetTaskPortScanner
{
    public enum PortStatus
    {
        Closed,
        Open,
        Smtp,
        Sntp,
        Pop,
        Dns,
        Http
    }

    public static class Program
    {
        public static void Main()
        {
            string host;
            do
            {
                Console.Write("Host: ");
                host = Console.ReadLine();
            } while (!ValidateHost(host));

            var pingResult = TryValidateConnectionByPing(host);
            if (pingResult == null)
                return;

            Console.WriteLine($"Ping result: success, {pingResult.RoundtripTime}ms");
            var timeout = Math.Max(100, (int) (pingResult.RoundtripTime) * 2);

            if (pingResult.Status != IPStatus.Success)
            {
                Console.WriteLine("Invalid ping result: " + pingResult.Status);
                return;
            }

            ushort startPort;
            do
            {
                Console.Write("Start port: ");
            } while (!ValidateUshortParse(out startPort));


            ushort endPort;
            do
            {
                Console.Write("End port: ");
            } while (!ValidateUshortParse(out endPort) || !ValidatePorts(endPort, startPort));

            Console.WriteLine($"{"Port",-7} {"TCP",-10} {"UDP",-10}");
            var tasks = new List<Task>();

            for (var port = startPort; port <= endPort; port++)
                tasks.Add(PrintPortStatus(host, port, timeout));

            Task.WaitAll(tasks.ToArray());
        }

        private static PingReply TryValidateConnectionByPing(string host)
        {
            try
            {
                return new Ping().Send(host);
            }
            catch (PingException pingException)
            {
                Exception e = pingException;
                var messages = new List<string>();
                while (e != null)
                {
                    messages.Add(e.Message);
                    e = e.InnerException;
                }

                Console.WriteLine(string.Join(": ", messages));
                return null;
            }
        }

        private static bool ValidatePorts(ushort endPort, ushort startPort)
        {
            var isValid = startPort <= endPort;
            if (!isValid)
                Console.WriteLine("End port must be more or equal than start port!");
            return isValid;
        }

        private static bool ValidateUshortParse(out ushort startPort)
        {
            var success = ushort.TryParse(Console.ReadLine(), out startPort);
            if (!success)
                Console.WriteLine("Invalid port.");
            return success;
        }

        private static bool ValidateHost(string host)
        {
            var isValid = Uri.CheckHostName(host) != UriHostNameType.Unknown;
            if (!isValid)
                Console.WriteLine("Invalid host.");
            return isValid;
        }

        private static async Task PrintPortStatus(string ip, int port, int timeoutMilliseconds)
        {
            var tcpTask = Task.Run(() => TestTcpPort(ip, port, timeoutMilliseconds));
            var udpTask = Task.Run(() => TestUdpPort(ip, port, timeoutMilliseconds));
            await tcpTask;
            await udpTask;
            Console.WriteLine($"{port,-7} {tcpTask.Result,-10} {udpTask.Result,-10}");
        }

        private static PortStatus TestUdpPort(string ip, int port, int timeoutMilliseconds)
        {
            var isOpen = TestUdpPortIsOpen(ip, port, timeoutMilliseconds);
            if (!isOpen)
                return PortStatus.Closed;

            if (TestUdpForDns(ip, port, timeoutMilliseconds))
                return PortStatus.Dns;

            if (TestUdpForSntp(ip, port, timeoutMilliseconds))
                return PortStatus.Sntp;

            return PortStatus.Open;
        }

        private static PortStatus TestTcpPort(string ip, int port, int timeoutMilliseconds)
        {
            var isOpen = TestTcpPortIsOpen(ip, port);
            if (!isOpen)
                return PortStatus.Closed;

            if (TestTcpForDns(ip, port, timeoutMilliseconds))
                return PortStatus.Dns;

            if (TestTcpForHttp(ip, port, timeoutMilliseconds))
                return PortStatus.Http;

            if (TestTcpForPop(ip, port, timeoutMilliseconds))
                return PortStatus.Pop;

            if (TestTcpForSmtp(ip, port, timeoutMilliseconds))
                return PortStatus.Smtp;

            return PortStatus.Open;
        }

        private static bool TestTcpPortIsOpen(string ip, int port)
        {
            using (var c = new TcpClient())
                try
                {
                    c.Connect(ip, port);
                }
                catch (Exception)
                {
                    return false;
                }

            return true;
        }

        private static bool TestUdpPortIsOpen(string ip, int port, int timeoutMillis = 1000)
        {
            using (var c = new UdpClient(ip, port))
            {
                var b = Encoding.Default.GetBytes("Hello!");

                try
                {
                    c.Send(b, b.Length);

                    var result = c.BeginReceive(null, null);
                    result.AsyncWaitHandle.WaitOne(TimeSpan.FromMilliseconds(timeoutMillis));

                    if (!result.IsCompleted) return true;

                    IPEndPoint endPoint = null;

                    c.EndReceive(result, ref endPoint);
                }
                catch (SocketException)
                {
                    return false;
                }

                return true;
            }
        }

        private static bool TestTcpForHttp(string ip, int port, int timeoutMillis = 1000)
        {
            using (var c = new TcpClient())
                try
                {
                    c.Connect(ip, port);

                    var b = Encoding.ASCII.GetBytes("GET / HTTP/1.0\r\n\r\n");

                    var stream = c.GetStream();
                    stream.Write(b, 0, b.Length);
                    var buf = new byte[4];
                    stream.ReadTimeout = timeoutMillis;
                    var readBytes = stream.Read(buf, 0, buf.Length);
                    return readBytes == 4 && buf.SequenceEqual(new byte[] {0x48, 0x54, 0x54, 0x50});
                }
                catch (Exception)
                {
                    return false;
                }
        }

        private static readonly byte[] DnsSimpleMessage =
        {
            0x15, 0xfa, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x06, 0x67, 0x6f, 0x6f,
            0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00,
            0x00, 0x01, 0x00, 0x01
        };

        private static bool TestUdpForDns(string ip, int port, int timeoutMillis = 1000)
        {
            using (var c = new UdpClient(ip, port))
            {
                byte[] buf;
                try
                {
                    c.Send(DnsSimpleMessage, DnsSimpleMessage.Length);

                    var result = c.BeginReceive(null, null);
                    result.AsyncWaitHandle.WaitOne(TimeSpan.FromMilliseconds(timeoutMillis));

                    if (!result.IsCompleted) return false;

                    IPEndPoint endPoint = null;


                    buf = c.EndReceive(result, ref endPoint);
                }
                catch (SocketException)
                {
                    return false;
                }

                return buf.Length >= 3 &&
                       buf[0] == DnsSimpleMessage[0] &&
                       buf[1] == DnsSimpleMessage[1] &&
                       (buf[2] & 0xf0) != 0;
            }
        }

        private static bool TestTcpForDns(string ip, int port, int timeoutMillis = 1000)
        {
            using (var tcpClient = new TcpClient())
                try
                {
                    tcpClient.Connect(ip, port);

                    var stream = tcpClient.GetStream();

                    var intBytes = BitConverter.GetBytes((ushort) DnsSimpleMessage.Length);

                    if (BitConverter.IsLittleEndian)
                        Array.Reverse(intBytes);

                    intBytes = intBytes.Concat(DnsSimpleMessage).ToArray();

                    stream.Write(intBytes, 0, intBytes.Length);

                    var buf = new byte[3 + 2];
                    stream.ReadTimeout = timeoutMillis;
                    int readBytes;
                    try
                    {
                        readBytes = stream.Read(buf, 0, buf.Length);
                    }
                    catch (IOException)
                    {
                        return false;
                    }

                    stream.Close();
                    tcpClient.Close();

                    return readBytes == 3 + 2 &&
                           buf[0 + 2] == DnsSimpleMessage[0] &&
                           buf[1 + 2] == DnsSimpleMessage[1] &&
                           (buf[2 + 2] & 0xf0) != 0;
                }
                catch (SocketException)
                {
                    return false;
                }
        }

        private static bool TestTcpForSmtp(string ip, int port, int timeoutMillis = 1000)
        {
            try
            {
                var split = ConnectAndReadSslTcp(ip, port, timeoutMillis).Split().Where(s => s.Length > 0).ToList();
                return split.Count >= 3 && (split[2] == "SMTP" || split[2] == "ESMTP");
            }
            catch (Exception)
            {
                return false;
            }
        }

        private static bool TestTcpForPop(string ip, int port, int timeoutMillis = 1000)
        {
            try
            {
                var split = ConnectAndReadSslTcp(ip, port, timeoutMillis).Split().Where(s => s.Length > 0).ToList();
                return split.Count > 0 && split[0] == "+OK" &&
                       (split.Count < 2 || split[1].ToLowerInvariant().Contains("pop"));
            }
            catch (Exception)
            {
                return false;
            }
        }

        private static string ConnectAndReadSslTcp(string ip, int port, int timeoutMillis)
        {
            var sb = new StringBuilder();
            using (var tcpClient = new TcpClient())
            {
                tcpClient.Connect(ip, port);

                using (var sslStream = new SslStream(tcpClient.GetStream()))
                {
                    sslStream.AuthenticateAsClient(ip);
                    sslStream.ReadTimeout = timeoutMillis;

                    var decoder = Encoding.ASCII.GetDecoder();

                    var byteBuf = new byte[2048];
                    int bytesRead;
                    do
                    {
                        try
                        {
                            bytesRead = sslStream.Read(byteBuf, 0, byteBuf.Length);
                        }
                        catch (IOException)
                        {
                            break;
                        }

                        var charBuf = new char[decoder.GetCharCount(byteBuf, 0, bytesRead)];
                        decoder.GetChars(byteBuf, 0, bytesRead, charBuf, 0);
                        sb.Append(charBuf);
                    } while (bytesRead > 0);
                }
            }

            return sb.ToString();
        }

        private static readonly byte[] SntpMessage =
        {
            0xdb, 0x00, 0x11, 0xe9, 0x00, 0x00, 0x55, 0x5f, //0
            0x00, 0x05, 0x7a, 0xcc, 0x00, 0x00, 0x00, 0x00, //8
            0xde, 0x8e, 0x8a, 0x9f, 0x37, 0xa2, 0x41, 0xde, //16
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //24  Origin TS
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //32
            0xde, 0x8e, 0x91, 0x1b, 0x5b, 0x79, 0x65, 0x46 //40 Transmit TS
        };

        private static bool TestUdpForSntp(string ip, int port, int timeoutMillis = 1000)
        {
            using (var c = new UdpClient(ip, port))
            {
                byte[] buf;
                try
                {
                    c.Send(SntpMessage, SntpMessage.Length);

                    var result = c.BeginReceive(null, null);
                    result.AsyncWaitHandle.WaitOne(TimeSpan.FromMilliseconds(timeoutMillis));

                    if (!result.IsCompleted) return false;

                    IPEndPoint endPoint = null;

                    buf = c.EndReceive(result, ref endPoint);
                }
                catch (SocketException)
                {
                    return false;
                }

                return buf.Length >= 3 &&
                       (buf[0] & 0b00000100) != 0 && //NTP response is server
                       IsArraysPartsEqual(SntpMessage, 40, buf, 24, 8);
            }
        }

        private static bool IsArraysPartsEqual(byte[] arr1, int start1, byte[] arr2, int start2, int length)
        {
            if (!arr1.IsIndexInside(start1) ||
                !arr2.IsIndexInside(start2) ||
                !arr1.IsIndexInside(start1 + length - 1) ||
                !arr2.IsIndexInside(start2 + length - 1))
                return false;
            for (var i = 0; i < length; i++)
            {
                if (arr1[start1 + i] != arr2[start2 + i])
                    return false;
            }

            return true;
        }

        private static bool IsIndexInside<T>(this IReadOnlyCollection<T> arr, int index)
        {
            return index >= 0 && index < arr.Count;
        }
    }
}