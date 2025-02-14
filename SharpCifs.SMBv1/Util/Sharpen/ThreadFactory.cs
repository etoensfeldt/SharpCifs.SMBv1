using System.Threading.Tasks;

namespace SharpCifs.Util.Sharpen
{
    internal class ThreadFactory
    {
        public Thread NewThread(IRunnable r)
        {
            Thread t = new Thread(r);
            t.Start(true);

            return t;
        }
    }
}
