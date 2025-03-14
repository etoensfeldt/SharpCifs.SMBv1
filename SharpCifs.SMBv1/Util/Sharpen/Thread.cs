using SharpCifs.Util.DbsHelper;
using System;
using System.Threading;
using System.Threading.Tasks;

#nullable enable

namespace SharpCifs.Util.Sharpen
{
    public class Thread : IRunnable
    {
        public bool IsCanceled => _cancellationToken.IsCancellationRequested;
        public bool IsRunning => !_task.IsCompleted;

        private readonly IRunnable _runnable;
        private readonly CancellationToken _cancellationToken;
        private readonly string _name;

        private CancellationTokenSource? _canceller;
        private Task _task = Task.CompletedTask;

        private static readonly Thread _empty = new();
        public static Thread Empty => _empty;

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

        public string GetName() => _name;


        public virtual void Run(Thread current)
        {
        }

        public void Sleep(int milis)
        {
            System.Threading.Thread.Sleep(milis);
        }


        public void Start()
        {
            Task task = new(() =>
            {
                try
                {
                    _runnable.Run(this);
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
                    Interlocked.Exchange(ref _canceller, null)?.Dispose();
                }
            }, _cancellationToken);

            if (Interlocked.CompareExchange(ref _task, task, Task.CompletedTask) != Task.CompletedTask)
                throw new InvalidOperationException("Thread already started.");

            task.Start(TaskScheduler.Default);
        }


        public void Cancel(bool isSynced)
        {
            var canceller = Interlocked.Exchange(ref _canceller, null);
            canceller?.Cancel(true);
            canceller?.Dispose();

            if (isSynced)
                while (IsRunning)
                    Sleep(100);
        }


        public bool Equals(Thread? thread)
        {
            return _task is not null &&
                   thread?._task is not null &&
                   _task.Id == thread._task.Id;
        }


        public void Dispose()
        {
            Interlocked.Exchange(ref _canceller, null)?.Dispose();
        }
    }
}
