// This code is derived from jcifs smb client library <jcifs at samba dot org>
// Ported by J. Arturo <webmaster at komodosoft dot net>
//  
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 2.1 of the License, or (at your option) any later version.
// 
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
// 
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
using System;
using System.IO;
using SharpCifs.Smb;
using SharpCifs.Util.Sharpen;
using Interlocked = System.Threading.Interlocked;

#nullable enable

namespace SharpCifs.Util.Transport
{
    /// <summary>
    /// This class simplifies communication for protocols that support
    /// multiplexing requests.
    /// </summary>
    /// <remarks>
    /// This class simplifies communication for protocols that support
    /// multiplexing requests. It encapsulates a stream and some protocol
    /// knowledge (provided by a concrete subclass) so that connecting,
    /// disconnecting, sending, and receiving can be syncronized
    /// properly. Apparatus is provided to send and receive requests
    /// concurrently.
    /// </remarks>
    public abstract class Transport : IRunnable
    {
        private static int s_id;

        private readonly string _name = $"Transport{Interlocked.Increment(ref s_id)}";

        private int _state;
        private Thread? _thread = null;
        private TransportException? _transportEx;

        protected internal Hashtable _responseMap = new Hashtable();

        public LogStream Log => LogStream.GetInstance();

        /// <exception cref="System.IO.IOException"></exception>
        public static int Readn(InputStream @in, byte[] b, int off, int len)
        {
            int i = 0;
            int n = -5;
            while (i < len)
            {
                n = @in.Read(b, off + i, len - i);
                if (n <= 0)
                {
                    break;
                }
                i += n;
            }
            return i;
        }

        /// <exception cref="System.IO.IOException"></exception>
        protected internal abstract void MakeKey(ServerMessageBlock request);

        /// <exception cref="System.IO.IOException"></exception>
        protected internal abstract ServerMessageBlock? PeekKey();

        /// <exception cref="System.IO.IOException"></exception>
        protected internal abstract void DoSend(ServerMessageBlock request);

        /// <exception cref="System.IO.IOException"></exception>
        protected internal abstract void DoRecv(Response response);

        /// <exception cref="System.IO.IOException"></exception>
        protected internal abstract void DoSkip();

        /// <exception cref="System.IO.IOException"></exception>
        public virtual void Sendrecv(ServerMessageBlock request, Response response, long timeout)
        {
            lock (this)
            {
                MakeKey(request);
                response.IsReceived = false;
                try
                {
                    _responseMap.Put(request, response);
                    DoSend(request);
                    response.Expiration = Runtime.CurrentTimeMillis() + timeout;
                    while (!response.IsReceived)
                    {
                        Runtime.Wait(this, timeout);
                        timeout = response.Expiration - Runtime.CurrentTimeMillis();
                        if (timeout <= 0)
                        {
                            throw new TransportException(
                                _name + " timedout waiting for response to " + request);
                        }
                    }
                }
                catch (IOException ioe)
                {
                    if (Log.Level > 2)
                    {
                        Runtime.PrintStackTrace(ioe, Log);
                    }
                    try
                    {
                        Disconnect(true);
                    }
                    catch (IOException ioe2)
                    {
                        Runtime.PrintStackTrace(ioe2, Log);
                    }
                    throw;
                }
                catch (Exception ie)
                {
                    throw new TransportException(ie);
                }
                finally
                {
                    //Sharpen.Collections.Remove(response_map, request);
                    _responseMap.Remove(request);
                }
            }
        }

        private void Loop(Thread thread)
        {
            while (Thread.CurrentThread().Equals(thread))
            {
                if (thread.IsCanceled)
                    break;

                try
                {
                    ServerMessageBlock key = PeekKey();
                    if (key == null)
                    {
                        throw new IOException("end of stream");
                    }

                    lock (this)
                    {
                        if (thread.IsCanceled)
                            break;

                        Response response = (Response)_responseMap.Get(key);
                        if (response == null)
                        {
                            if (Log.Level >= 4)
                            {
                                Log.WriteLine("Invalid key, skipping message");
                            }
                            DoSkip();
                        }
                        else
                        {
                            DoRecv(response);

                            if (thread.IsCanceled)
                                break;

                            response.IsReceived = true;
                            Runtime.NotifyAll(this);
                        }
                    }
                }
                catch (Exception ex)
                {
                    string msg = ex.Message;
                    bool timeout = msg != null && msg.Equals("Read timed out");
                    bool hard = timeout == false;

                    if (!timeout && Log.Level >= 3)
                    {
                        Runtime.PrintStackTrace(ex, Log);
                    }

                    try
                    {
                        Disconnect(hard);
                    }
                    catch (IOException ioe)
                    {
                        Runtime.PrintStackTrace(ioe, Log);
                    }
                }
            }
        }

        /// <exception cref="System.Exception"></exception>
        protected internal abstract void DoConnect();

        /// <exception cref="System.IO.IOException"></exception>
        protected internal abstract void DoDisconnect(bool hard);

        /// <exception cref="SharpCifs.Util.Transport.TransportException"></exception>
        public virtual void Connect(long timeout)
        {
            lock (this)
            {
                Thread? thread = null;
                try
                {
                    switch (_state)
                    {
                        case 0:
                            {
                                break;
                            }

                        case 3:
                            {
                                return;
                            }

                        case 4:
                            {
                                // already connected
                                _state = 0;
                                throw new TransportException("Connection in error", _transportEx);
                            }

                        default:
                            {
                                //TransportException te = new TransportException("Invalid state: " + state);
                                _state = 0;
                                throw new TransportException("Invalid state: " + _state);
                            }
                    }
                    _state = 1;
                    _transportEx = null;

                    thread = new(this);
                    ClearThread(thread);
                    
                    lock (thread)
                    {
                        thread.Start(true);

                        if (!thread.IsCanceled)
                            Runtime.Wait(thread, timeout);
                    }

                    switch (_state)
                    {
                        case 1:
                        {
                            _state = 0;
                            CompareClearThread(thread);
                            throw new TransportException("Connection timeout");
                        }

                        case 2:
                        {
                            if (_transportEx != null)
                            {
                                _state = 4;
                                CompareClearThread(thread);
                                throw _transportEx;
                            }
                            _state = 3;
                            return;
                        }
                    }
                }
                catch (Exception ie)
                {
                    _state = 0;

                    if (thread is not null)
                        CompareClearThread(thread);

                    throw new TransportException(ie);
                }
                finally
                {
                    if (_state != 0 && _state != 3 && _state != 4)
                    {
                        if (Log.Level >= 1)
                        {
                            Log.WriteLine("Invalid state: " + _state);
                        }
                        _state = 0;

                        if (thread is not null)
                            CompareClearThread(thread);
                    }
                }
            }
        }

        /// <exception cref="System.IO.IOException"></exception>
        public virtual void Disconnect(bool hard)
        {

            if (hard)
            {
                IOException? ioe = null;
                switch (_state)
                {
                    case 0:
                        {
                            return;
                        }

                    case 2:
                        {
                            hard = true;
                            goto case 3;
                        }

                    case 3:
                        {
                            if (_responseMap.Count != 0 && !hard)
                            {
                                break;
                            }
                            try
                            {
                                DoDisconnect(hard);
                            }
                            catch (IOException ioe0)
                            {
                                ioe = ioe0;
                            }
                            goto case 4;
                        }

                    case 4:
                        {
                            ClearThread();
                            _state = 0;
                            break;
                        }

                    default:
                        {
                            if (Log.Level >= 1)
                            {
                                Log.WriteLine("Invalid state: " + _state);
                            }
                            ClearThread();
                            _state = 0;
                            break;
                        }
                }
                if (ioe != null)
                {
                    throw ioe;
                }

                return;
            }

            lock (this)
            {
                IOException? ioe = null;
                switch (_state)
                {
                    case 0:
                        {
                            return;
                        }

                    case 2:
                        {
                            hard = true;
                            goto case 3;
                        }

                    case 3:
                        {
                            if (_responseMap.Count != 0 && !hard)
                            {
                                break;
                            }
                            try
                            {
                                DoDisconnect(hard);
                            }
                            catch (IOException ioe0)
                            {
                                ioe = ioe0;
                            }
                            goto case 4;
                        }

                    case 4:
                        {
                            ClearThread();
                            _state = 0;
                            break;
                        }

                    default:
                        {
                            if (Log.Level >= 1)
                            {
                                Log.WriteLine("Invalid state: " + _state);
                            }
                            ClearThread();
                            _state = 0;
                            break;
                        }
                }
                if (ioe != null)
                {
                    throw ioe;
                }
            }
        }

        public virtual void Run()
        {
            Thread runThread = Thread.CurrentThread();

            if (runThread.IsCanceled)
                return;

            Exception? ex0 = null;
            try
            {
                DoConnect();
            }
            catch (Exception ex)
            {
                ex0 = ex;
                // Defer to below where we're locked
                return;
            }
            finally
            {
                lock (runThread)
                {
                    if (!runThread.IsCanceled)
                    {
                        if (!runThread.Equals(_thread))
                        {
                            if (ex0 != null)
                            {
                                if (Log.Level >= 2)
                                {
                                    Runtime.PrintStackTrace(ex0, Log);
                                }
                            }
                            //return;
                        }
                        if (ex0 != null)
                        {
                            _transportEx = new TransportException(ex0);
                        }
                        _state = 2;
                        // run connected
                        Runtime.Notify(runThread);
                    }
                }
            }

            if (runThread.IsCanceled)
                return;

            Loop(runThread);
        }

        public override string ToString()
        {
            return _name;
        }

        private void ClearThread(Thread? replacement = null)
        {
            Thread? oldThread = Interlocked.Exchange(ref _thread, replacement);
            oldThread?.Cancel(true);
            oldThread?.Dispose();
        }

        private void CompareClearThread(Thread comparand, Thread? replacement = null)
        {
            if (Interlocked.CompareExchange(ref _thread, replacement, comparand) == comparand)
            {
                comparand.Cancel(true);
                comparand.Dispose();
            }
            else
            {
                // Comparand thread already disposed
                // Wait for cancel to finish
                comparand.Cancel(true);
            }
        }
    }
}
