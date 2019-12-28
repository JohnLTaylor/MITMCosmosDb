using System.Threading.Tasks;

namespace MITMCosmosDb
{
    class Program
    {
        static async Task Main()
        {
            await SslTcpServer.RunServer();
        }
    }
}
