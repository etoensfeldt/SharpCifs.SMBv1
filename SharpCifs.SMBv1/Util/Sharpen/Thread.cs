using System;
using System.Threading;
using System.Threading.Tasks;

#nullable enable

namespace SharpCifs.Util.Sharpen
{
    public class Thread : IRunnable
    {
        [ThreadStatic]
        private static Thread? WrapperThread;

        public static Thread CurrentThread()
        {
            if (WrapperThread == null)
            {
                LogStream.GetInstance().WriteLine("Wrapper thread for {0} was not set", Environment.CurrentManagedThreadId);
                WrapperThread = new Thread(Environment.CurrentManagedThreadId);
            }

            return WrapperThread;
        }

        public bool IsCanceled => _cancellationToken.IsCancellationRequested;
        public bool IsRunning => _isRunning != 0;

        private readonly IRunnable _runnable;
        private readonly CancellationToken _cancellationToken;
        private readonly string _name;

        private CancellationTokenSource? _canceller;
        private int? _id = null;
        private int _isRunning = 0; // 0 == false


        public Thread() : this(null, null)
        {
        }


        public Thread(string? name) : this(null, name)
        {
        }


        public Thread(IRunnable? runnable) : this(runnable, null)
        {
        }


        private Thread(IRunnable? runnable, string? name)
        {
            _runnable = runnable ?? this;
            _canceller = new();
            _cancellationToken = _canceller.Token;
            _name = name ?? string.Empty;
        }


        private Thread(int threadId)
        {
            _id = threadId;
            _runnable = this;
            _canceller = new();
            _cancellationToken = _canceller.Token;
            _name = string.Empty;
        }


        public string GetName() => _name;


        public virtual void Run()
        {
        }


        public static void Sleep(long milis, CancellationToken token = default)
        {
            Task.Delay((int)milis, token).ContinueWith(_ => { }).Wait();
        }


        public void Start(bool isSynced = false)
        {
            if (Interlocked.CompareExchange(ref _isRunning, 1, 0) == 1)
                throw new InvalidOperationException("Thread already started.");

            bool hasStarted = false;
            
            _ = Task.Run(() =>
            {
                WrapperThread = this;
                _id = Environment.CurrentManagedThreadId;

                hasStarted = true;
                
                try
                {
                    _runnable.Run();
                }
                catch (TaskCanceledException)
                {
                    Console.WriteLine("SMBv1 thread cancelled while running");
                }
                catch (Exception exception)
                {
                    Console.WriteLine(exception);
                }
                finally
                {
                    _isRunning = 0;                    
                    Interlocked.Exchange(ref _canceller, null)?.Dispose();
                }
            }, _cancellationToken);

            if (isSynced)
                while (!hasStarted)
                    Sleep(300, _cancellationToken);
        }


        public void Cancel(bool isSynced = false)
        {
            Interlocked.Exchange(ref _canceller, null)?.Cancel(true);

            if (isSynced)
                while (IsRunning)
                    Sleep(300);
        }


        public bool Equals(Thread? thread)
        {
            if (thread == null)
                return false;

            if (_id == null
                || thread._id == null)
                return false;

            return _id == thread._id;
        }


        public void Dispose()
        {
            Interlocked.Exchange(ref _canceller, null)?.Dispose();
            _isRunning = 0;
            _id = null;
        }
    }
}
