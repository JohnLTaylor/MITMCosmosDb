using System;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace MITMCosmosDb
{
    internal class SslTcpServer
    {
        private static X509Certificate serverCertificate = null;

        internal static async Task RunServer()
        {
            serverCertificate = LoadCertificateFromStore();

            var listener = new TcpListener(IPAddress.Any, 8082);
            listener.Start();

            while (true)
            {
                Console.WriteLine("Waiting for a client to connect...");
                TcpClient client = await listener.AcceptTcpClientAsync();
                _ = ProcessClient(client);
            }
        }

        private static X509Certificate LoadCertificateFromStore()
        {
            X509Store store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
            store.Open(OpenFlags.ReadOnly);

            try
            {
                foreach (var cert in store.Certificates)
                {
                    if (cert.FriendlyName == "DocumentDbEmulatorCertificate")
                    {
                        return cert;
                    }
                }
            }
            finally
            {
                store.Close();
            }

            throw new Exception("DocumentDbEmulatorCertificate cert is missing for local store");
        }

        private static async Task ProcessClient(TcpClient server)
        {
            var sslServerStream = new SslStream(server.GetStream(), false);

            try
            {
                await sslServerStream.AuthenticateAsServerAsync(serverCertificate, clientCertificateRequired: false, checkCertificateRevocation: false);

                try
                {
                    var client = new TcpClient("127.0.0.1", 8081);
                    var sslClientStream = new SslStream(client.GetStream(), false);

                    try
                    {
                        await sslClientStream.AuthenticateAsClientAsync("127.0.0.1");
                        await Task.WhenAll(Proxy(sslServerStream, sslClientStream, "S->C"), Proxy(sslClientStream, sslServerStream, "C->S"));
                    }
                    finally
                    {
                        sslClientStream.Close();
                        client.Close();
                    }
                }
                catch (Exception e)
                {
                    Console.WriteLine("Client Exception: {0}", e.Message);
                    if (e.InnerException != null)
                    {
                        Console.WriteLine("Inner exception: {0}", e.InnerException.Message);
                    }
                }
            }
            catch (Exception e)
            {
                Console.WriteLine("Server Exception: {0}", e.Message);
                if (e.InnerException != null)
                {
                    Console.WriteLine("Inner exception: {0}", e.InnerException.Message);
                }
            }
            finally
            {
                sslServerStream.Close();
                server.Close();
            }
        }

        private static async Task Proxy(SslStream sslReadStream, SslStream sslWriteStream, string description)
        {
            var buffer = new byte[8192];

            while (true)
            {
                int read = await sslReadStream.ReadAsync(buffer, 0, buffer.Length);

                if ( read == 0)
                    return;

                var msg = Encoding.UTF8.GetString(new Span<byte>(buffer, 0, read));

                Console.WriteLine($"{description}: {msg}");

                if (msg.Contains("127.0.0.1:8081"))
                {
                    msg = msg.Replace("127.0.0.1:8081", "127.0.0.1:8082");
                    var tmpBuffer = Encoding.UTF8.GetBytes(msg);
                    await sslWriteStream.WriteAsync(tmpBuffer, 0, tmpBuffer.Length);
                }
                else
                {
                    await sslWriteStream.WriteAsync(buffer, 0, read);
                }
            }
        }
    }
}