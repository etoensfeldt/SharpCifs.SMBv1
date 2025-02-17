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
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using SharpCifs.Netbios;
using SharpCifs.Util;
using SharpCifs.Util.Sharpen;
using SharpCifs.Util.Transport;

#nullable enable

namespace SharpCifs.Smb
{
    public class SmbTransport : Transport
    {
        private static readonly byte[] s_buffer = new byte[0xFFFF];
        private static readonly SmbComNegotiate s_negotiateRequest = new SmbComNegotiate();
        private static readonly List<SmbTransport> s_connections = new List<SmbTransport>();

        internal static LogStream LogStatic = LogStream.GetInstance();

        internal static SmbTransport GetSmbTransport(UniAddress address,
                                                     int port,
                                                     IPAddress? localAddr = null,
                                                     int localPort = -1,
                                                     string? hostName = null)
        {
            localAddr ??= SmbConstants.Laddr;
            localPort = localPort == -1 ? SmbConstants.Lport : localPort;

            lock (typeof(SmbTransport))
            {
                SmbTransport? conn;

                lock (s_connections)
                {
                    if (SmbConstants.SsnLimit != 1)
                    {
                        conn = s_connections
                            .FirstOrDefault(c => c.Matches(address,
                                                            port,
                                                            localAddr,
                                                            localPort,
                                                            hostName)
                                                && (SmbConstants.SsnLimit == 0
                                                    || c._sessions.Count < SmbConstants.SsnLimit));

                        if (conn != null)
                        {
                            return conn;
                        }
                    }

                    conn = new SmbTransport(address, port, localAddr, localPort);
                    s_connections.Insert(0, conn);
                }
                return conn;
            }
        }


        /// <summary>
        /// Clear All Cached Transport-Connections
        /// </summary>
        public static void ClearCachedConnections(bool force = false)
        {
            lock (typeof(SmbTransport))
            lock (s_connections)
            {
                var failedTransport = new List<SmbTransport>();

                foreach (var transport in s_connections.ToArray())
                {
                    //強制破棄フラグONのとき、接続状態がどうであれ破棄する。
                    if (force)
                    {
                        s_connections.Remove(transport);

                        try { transport?.Disconnect(true); }
                        catch (Exception) { }

                        continue;
                    }

                    //即座に異常と分かるTransportは接続試行せず破棄対象にする。
                    if (transport._socket == null
                        || !transport._socket.Connected)
                    {
                        s_connections.Remove(transport);

                        try { transport?.Disconnect(true); }
                        catch (Exception) { }

                        continue;
                    }


                    //現在の接続状態を検証する。
                    //https://msdn.microsoft.com/ja-jp/library/system.net.sockets.socket.connected(v=vs.110).aspx
                    var isSocketBlocking = transport._socket.Blocking;
                    var isConnected = false;
                    try
                    {
                        var tmpBytes = new byte[1];
                        transport._socket.Blocking = false;
                        transport._socket.Send(tmpBytes, 0, 0);
                        isConnected = true;
                    }
                    catch (SocketException e)
                    {
                        if (e.SocketErrorCode == SocketError.WouldBlock)
                        {
                            //現在も接続中
                            isConnected = true;
                        }
                        else
                        {
                            //切断されている
                            isConnected = false;
                        }
                    }
                    catch (Exception)
                    {
                        //切断されている
                        isConnected = false;
                    }
                    finally
                    {
                        transport._socket.Blocking = isSocketBlocking;
                    }

                    if (!isConnected)
                    {
                        s_connections.Remove(transport);

                        try { transport?.Disconnect(true); }
                        catch (Exception) { }
                    }
                }
            }
        }


        internal class ServerData
        {
            internal byte Flags;

            internal int Flags2;

            internal int MaxMpxCount;

            internal int MaxBufferSize;

            internal int SessionKey;

            internal int Capabilities;

            internal string? OemDomainName;

            internal int SecurityMode;

            internal int Security;

            internal bool EncryptedPasswords;

            internal bool SignaturesEnabled;

            internal bool SignaturesRequired;

            internal int MaxNumberVcs;

            internal int MaxRawSize;

            internal long ServerTime;

            internal int ServerTimeZone;

            internal int EncryptionKeyLength;

            internal byte[]? EncryptionKey;

            internal byte[]? Guid;

            internal ServerData(SmbTransport enclosing)
            {
                this._enclosing = enclosing;
            }

            private readonly SmbTransport _enclosing;
        }

        private readonly IPAddress _localAddr;

        private readonly int _localPort;

        private readonly UniAddress _address;

        internal UniAddress Address => _address;

        private SocketEx? _socket;

        private OutputStream? _out;

        private InputStream? _in;

        private int _port;

        private int _mid;

        private readonly byte[] _smallBuffer = new byte[512];

        private readonly SmbComBlankResponse _key = new SmbComBlankResponse();

        private long _sessionExpiration = Runtime.CurrentTimeMillis() + SmbConstants.SoTimeout;

        internal SigningDigest? Digest;

        private readonly List<SmbSession> _sessions = new List<SmbSession>();

        internal readonly ServerData Server;

        internal int Flags2 = SmbConstants.Flags2;

        internal int MaxMpxCount = SmbConstants.MaxMpxCount;

        internal int SndBufSize = SmbConstants.SndBufSize;

        internal int RcvBufSize = SmbConstants.RcvBufSize;

        internal int Capabilities = SmbConstants.Capabilities;

        internal int SessionKey = 0x00000000;

        private bool _useUnicode = SmbConstants.UseUnicode;

        internal string? TconHostName;

        private SmbTransport(UniAddress address,
                             int port,
                             IPAddress localAddr,
                             int localPort)
        {
            Server = new ServerData(this);
            _address = address;
            _port = port;
            _localAddr = localAddr;
            _localPort = localPort;
        }

        internal virtual SmbSession GetSmbSession(NtlmPasswordAuthentication? auth = null)
        {
            auth ??= NtlmPasswordAuthentication.Null;

            lock (this)
            {
                SmbSession? ssn;
                long now;

                ssn = _sessions.FirstOrDefault(s => s.Matches(auth));
                if (ssn != null)
                {
                    ssn.Auth = auth;
                    return ssn;
                }

                if (SmbConstants.SoTimeout > 0
                    && _sessionExpiration < (now = Runtime.CurrentTimeMillis()))
                {
                    _sessionExpiration = now + SmbConstants.SoTimeout;

                    foreach (var session in _sessions.Where(s => s.Expiration < now))
                    {
                        session.Logoff(false);
                    }
                }
                ssn = new SmbSession(auth, this);
                _sessions.Add(ssn);
                return ssn;
            }
        }

        internal virtual bool Matches(UniAddress address,
                                      int port,
                                      IPAddress localAddr,
                                      int localPort,
                                      string? hostName)
        {
            hostName ??= address.GetHostName();

            return _localPort == localPort &&
                    (TconHostName == null || Runtime.EqualsIgnoreCase(hostName, TconHostName)) && 
                    address.Equals(_address) && 
                    (port == -1 || port == _port || (port == 445 && _port == 139)) && 
                    (localAddr == _localAddr || (localAddr != null && localAddr.Equals(_localAddr)));
        }

        /// <exception cref="SharpCifs.Smb.SmbException"></exception>
        internal virtual bool HasCapability(int cap)
        {
            try
            {
                Connect(SmbConstants.ResponseTimeout);
            }
            catch (IOException ioe)
            {
                throw new SmbException(ioe.Message, ioe);
            }
            return (Capabilities & cap) == cap;
        }

        internal virtual bool IsSignatureSetupRequired(NtlmPasswordAuthentication auth)
        {
            return (Flags2 & SmbConstants.Flags2SecuritySignatures) != 0
                   && Digest == null
                   && auth != NtlmPasswordAuthentication.Null
                   && NtlmPasswordAuthentication.Null.Equals(auth) == false;
        }

        /// <exception cref="System.IO.IOException"></exception>
        private void Ssn139()
        {
            Name calledName = new Name(_address.FirstCalledName(), 0x20, null);
            do
            {
                _socket = new SocketEx(AddressFamily.InterNetwork,
                                      SocketType.Stream,
                                      ProtocolType.Tcp);

                //TCPローカルポートは、毎回空いているものを使う。
                //https://blogs.msdn.microsoft.com/dgorti/2005/09/18/only-one-usage-of-each-socket-address-protocolnetwork-addressport-is-normally-permitted/
                _socket.Bind(new IPEndPoint(_localAddr, 0));

                _socket.Connect(new IPEndPoint(IPAddress.Parse(_address.GetHostAddress()), 
                                              139),
                               SmbConstants.ConnTimeout);
                
                _socket.SoTimeOut = SmbConstants.SoTimeout;

                _out = _socket.GetOutputStream();
                _in = _socket.GetInputStream();
                SessionServicePacket ssp = new SessionRequestPacket(calledName,
                                                                    NbtAddress.GetLocalName());
                _out.Write(_smallBuffer, 0, ssp.WriteWireFormat(_smallBuffer, 0));
                if (Readn(_in, _smallBuffer, 0, 4) < 4)
                {
                    try
                    {
                        //Socket.`Close` method deleted
                        //Socket.Close();
                        _socket.Dispose();
                    }
                    catch (IOException)
                    {
                    }
                    throw new SmbException("EOF during NetBIOS session request");
                }
                switch (_smallBuffer[0] & 0xFF)
                {
                    case SessionServicePacket.PositiveSessionResponse:
                        {
                            if (Log.Level >= 4)
                            {
                                Log.WriteLine("session established ok with " + _address);
                            }
                            return;
                        }

                    case SessionServicePacket.NegativeSessionResponse:
                        {
                            int errorCode = _in.Read() & 0xFF;
                            switch (errorCode)
                            {
                                case NbtException.CalledNotPresent:
                                case NbtException.NotListeningCalled:
                                    {
                                        //Socket.`Close` method deleted
                                        //Socket.Close();
                                        _socket.Dispose();
                                        break;
                                    }

                                default:
                                    {
                                        Disconnect(true);
                                        throw new NbtException(NbtException.ErrSsnSrvc,
                                                               errorCode);
                                    }
                            }
                            break;
                        }

                    case -1:
                        {
                            Disconnect(true);
                            throw new NbtException(NbtException.ErrSsnSrvc,
                                                   NbtException.ConnectionRefused);
                        }

                    default:
                        {
                            Disconnect(true);
                            throw new NbtException(NbtException.ErrSsnSrvc, 0);
                        }
                }
            }
            while ((calledName.name = _address.NextCalledName()) != null);
            throw new IOException("Failed to establish session with " + _address);
        }

        /// <exception cref="System.IO.IOException"></exception>
        private void Negotiate(int port, ServerMessageBlock resp)
        {
            lock (_smallBuffer)
            {
                if (port == 139)
                {
                    Ssn139();
                }
                else
                {
                    if (port == -1)
                    {
                        port = SmbConstants.DefaultPort;
                    }
                    // 445
                    _socket = new SocketEx(AddressFamily.InterNetwork,
                                          SocketType.Stream,
                                          ProtocolType.Tcp);

                    //TCPローカルポートは、毎回空いているものを使う。
                    //https://blogs.msdn.microsoft.com/dgorti/2005/09/18/only-one-usage-of-each-socket-address-protocolnetwork-addressport-is-normally-permitted/
                    _socket.Bind(new IPEndPoint(_localAddr, 0));

                    _socket.Connect(new IPEndPoint(IPAddress.Parse(_address.GetHostAddress()), 
                                                  port), // <- 445
                                   SmbConstants.ConnTimeout);

                    _socket.SoTimeOut = SmbConstants.SoTimeout;
                    _out = _socket.GetOutputStream();
                    _in = _socket.GetInputStream();
                }
                if (++_mid == 32000)
                {
                    _mid = 1;
                }
                s_negotiateRequest.Mid = _mid;
                int n = s_negotiateRequest.Encode(_smallBuffer, 4);
                Encdec.Enc_uint32be(n & 0xFFFF, _smallBuffer, 0);
                if (Log.Level >= 4)
                {
                    Log.WriteLine(s_negotiateRequest);
                    if (Log.Level >= 6)
                    {
                        Hexdump.ToHexdump(Log, _smallBuffer, 4, n);
                    }
                }
                _out!.Write(_smallBuffer, 0, 4 + n);
                _out!.Flush();
                if (PeekKey() == null)
                {
                    throw new IOException("transport closed in negotiate");
                }
                int size = Encdec.Dec_uint16be(_smallBuffer, 2) & 0xFFFF;
                if (size < 33 || (4 + size) > _smallBuffer.Length)
                {
                    throw new IOException("Invalid payload size: " + size);
                }
                Readn(_in!, _smallBuffer, 4 + 32, size - 32);
                resp.Decode(_smallBuffer, 4);
                if (Log.Level >= 4)
                {
                    Log.WriteLine(resp);
                    if (Log.Level >= 6)
                    {
                        Hexdump.ToHexdump(Log, _smallBuffer, 4, n);
                    }
                }
            }
        }

        /// <exception cref="SharpCifs.Smb.SmbException"></exception>
        public virtual void Connect()
        {
            try
            {
                base.Connect(SmbConstants.ResponseTimeout);
            }
            catch (TransportException te)
            {
                IPEndPoint? local = _socket?.LocalEndPoint as IPEndPoint;
                IPEndPoint? remote = _socket?.RemoteEndPoint as IPEndPoint;

                // IO Exception
                throw new SmbException($"Failed to connect, {_address}  [ {local?.Address}:{local?.Port} --> {remote?.Address}:{remote?.Port} ]", te);
            }
        }

        /// <exception cref="System.IO.IOException"></exception>
        protected internal override void DoConnect()
        {
            SmbComNegotiateResponse resp = new SmbComNegotiateResponse(Server);
            try
            {
                Negotiate(_port, resp);
            }
            catch (ConnectException)
            {
                _port = (_port == -1 || _port == SmbConstants.DefaultPort)
                            ? 139
                            : SmbConstants.DefaultPort;
                Negotiate(_port, resp);
            }
            if (resp.DialectIndex > 10)
            {
                throw new SmbException("This client does not support the negotiated dialect.");
            }
            if (
                (Server.Capabilities & SmbConstants.CapExtendedSecurity)
                    != SmbConstants.CapExtendedSecurity
                && Server.EncryptionKeyLength != 8
                && SmbConstants.LmCompatibility == 0
            )
            {
                throw new SmbException("Unexpected encryption key length: "
                                       + Server.EncryptionKeyLength);
            }
            TconHostName = _address.GetHostName();
            if (Server.SignaturesRequired
                || (Server.SignaturesEnabled && SmbConstants.Signpref))
            {
                Flags2 |= SmbConstants.Flags2SecuritySignatures;
            }
            else
            {
                Flags2 &= 0xFFFF ^ SmbConstants.Flags2SecuritySignatures;
            }
            MaxMpxCount = Math.Min(MaxMpxCount, Server.MaxMpxCount);
            if (MaxMpxCount < 1)
            {
                MaxMpxCount = 1;
            }
            SndBufSize = Math.Min(SndBufSize, Server.MaxBufferSize);
            Capabilities &= Server.Capabilities;
            if ((Server.Capabilities & SmbConstants.CapExtendedSecurity)
                    == SmbConstants.CapExtendedSecurity)
            {
                Capabilities |= SmbConstants.CapExtendedSecurity;
            }
            // & doesn't copy high bit
            if ((Capabilities & SmbConstants.CapUnicode) == 0)
            {
                // server doesn't want unicode
                if (SmbConstants.ForceUnicode)
                {
                    Capabilities |= SmbConstants.CapUnicode;
                }
                else
                {
                    _useUnicode = false;
                    Flags2 &= 0xFFFF ^ SmbConstants.Flags2Unicode;
                }
            }
        }

        /// <exception cref="System.IO.IOException"></exception>
        protected internal override void DoDisconnect(bool hard)
        {
            try
            {
                if (_sessions != null)
                    foreach (var ssn in _sessions)
                        ssn?.Logoff(hard);

                _out?.Close();
                _in?.Close();

                //Socket.`Close` method deleted
                //Socket.Close();
                _socket?.Shutdown(SocketShutdown.Both);
                _socket?.Dispose();
            }
            finally
            {
                Digest = null;
                _socket = null;
                TconHostName = null;
            }

        }

        /// <exception cref="System.IO.IOException"></exception>
        protected internal override void MakeKey(ServerMessageBlock request)
        {
            if (++_mid == 32000)
            {
                _mid = 1;
            }
            request.Mid = _mid;
        }

        /// <exception cref="System.IO.IOException"></exception>
        protected internal override ServerMessageBlock? PeekKey()
        {
            if (_in is null)
                throw new NullReferenceException(nameof(_in));

            int n;
            do
            {
                if ((n = Readn(_in, _smallBuffer, 0, 4)) < 4)
                {
                    return null;
                }
            }
            while (_smallBuffer[0] == 0x85);
            if ((n = Readn(_in, _smallBuffer, 4, 32)) < 32)
            {
                return null;
            }
            if (Log.Level >= 4)
            {
                Log.WriteLine("New data read: " + this);
                Hexdump.ToHexdump(Log, _smallBuffer, 4, 32);
            }
            for (;;)
            {
                if (_smallBuffer[0] == 0x00 && _smallBuffer[1] == 0x00 &&
                    _smallBuffer[4] == 0xFF &&
                    _smallBuffer[5] == 'S' &&
                    _smallBuffer[6] == 'M' &&
                    _smallBuffer[7] == 'B')
                {
                    break;
                }
                for (int i = 0; i < 35; i++)
                {
                    _smallBuffer[i] = _smallBuffer[i + 1];
                }
                int b;
                if ((b = _in.Read()) == -1)
                {
                    return null;
                }
                _smallBuffer[35] = unchecked((byte)b);
            }
            _key.Mid = Encdec.Dec_uint16le(_smallBuffer, 34) & 0xFFFF;
            return _key;
        }

        /// <exception cref="System.IO.IOException"></exception>
        protected internal override void DoSend(ServerMessageBlock request)
        {
            if (_out is null)
                throw new NullReferenceException(nameof(_out));

            lock (s_buffer)
            {
                ServerMessageBlock smb = request;
                int n = smb.Encode(s_buffer, 4);
                Encdec.Enc_uint32be(n & 0xFFFF, s_buffer, 0);
                if (Log.Level >= 4)
                {
                    do
                    {
                        Log.WriteLine(smb);
                    }
                    while (smb is AndXServerMessageBlock
                           && (smb = ((AndXServerMessageBlock)smb).Andx) != null);
                    if (Log.Level >= 6)
                    {
                        Hexdump.ToHexdump(Log, s_buffer, 4, n);
                    }
                }
                _out.Write(s_buffer, 0, 4 + n);
            }
        }

        /// <exception cref="System.IO.IOException"></exception>
        protected internal virtual void DoSend0(ServerMessageBlock request)
        {
            try
            {
                DoSend(request);
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
        }

        /// <exception cref="System.IO.IOException"></exception>
        protected internal override void DoRecv(Response response)
        {
            if (_in is null)
                throw new NullReferenceException(nameof(_in));

            ServerMessageBlock resp = (ServerMessageBlock)response;
            resp.UseUnicode = _useUnicode;
            resp.ExtendedSecurity
                = (Capabilities & SmbConstants.CapExtendedSecurity)
                    == SmbConstants.CapExtendedSecurity;
            lock (s_buffer)
            {
                Array.Copy(_smallBuffer, 0, s_buffer, 0, 4 + SmbConstants.HeaderLength);
                int size = Encdec.Dec_uint16be(s_buffer, 2) & 0xFFFF;
                if (size < (SmbConstants.HeaderLength + 1) || (4 + size) > RcvBufSize)
                {
                    throw new IOException("Invalid payload size: " + size);
                }
                int errorCode = Encdec.Dec_uint32le(s_buffer, 9) & unchecked((int)(0xFFFFFFFF));
                if (resp.Command == ServerMessageBlock.SmbComReadAndx
                    && (errorCode == 0
                        || errorCode == unchecked((int)(0x80000005)))
                )
                {
                    // overflow indicator normal for pipe
                    SmbComReadAndXResponse r = (SmbComReadAndXResponse)resp;
                    int off = SmbConstants.HeaderLength;
                    Readn(_in, s_buffer, 4 + off, 27);
                    off += 27;
                    resp.Decode(s_buffer, 4);
                    int pad = r.DataOffset - off;
                    if (r.ByteCount > 0 && pad > 0 && pad < 4)
                    {
                        Readn(_in, s_buffer, 4 + off, pad);
                    }
                    if (r.DataLength > 0)
                    {
                        Readn(_in, r.B, r.Off, r.DataLength);
                    }
                }
                else
                {
                    Readn(_in, s_buffer, 4 + 32, size - 32);
                    resp.Decode(s_buffer, 4);
                    if (resp is SmbComTransactionResponse)
                    {
                        ((SmbComTransactionResponse)resp).Current();
                    }
                }
                if (Digest != null && resp.ErrorCode == 0)
                {
                    Digest.Verify(s_buffer, 4, resp);
                }
                if (Log.Level >= 4)
                {
                    Log.WriteLine(response);
                    if (Log.Level >= 6)
                    {
                        Hexdump.ToHexdump(Log, s_buffer, 4, size);
                    }
                }
            }
        }

        /// <exception cref="System.IO.IOException"></exception>
        protected internal override void DoSkip()
        {
            if (_in is null)
                throw new NullReferenceException(nameof(_in));

            int size = Encdec.Dec_uint16be(_smallBuffer, 2) & 0xFFFF;
            if (size < 33 || (4 + size) > RcvBufSize)
            {
                _in.Skip(_in.Available());
            }
            else
            {
                _in.Skip(size - 32);
            }
        }

        /// <exception cref="SharpCifs.Smb.SmbException"></exception>
        internal virtual void CheckStatus(ServerMessageBlock req, ServerMessageBlock resp)
        {
            resp.ErrorCode = SmbException.GetStatusByCode(resp.ErrorCode);
            switch (resp.ErrorCode)
            {
                case NtStatus.NtStatusOk:
                    {
                        break;
                    }

                case NtStatus.NtStatusAccessDenied:
                case NtStatus.NtStatusWrongPassword:
                case NtStatus.NtStatusLogonFailure:
                case NtStatus.NtStatusAccountRestriction:
                case NtStatus.NtStatusInvalidLogonHours:
                case NtStatus.NtStatusInvalidWorkstation:
                case NtStatus.NtStatusPasswordExpired:
                case NtStatus.NtStatusAccountDisabled:
                case NtStatus.NtStatusAccountLockedOut:
                case NtStatus.NtStatusTrustedDomainFailure:
                    {
                        throw new SmbAuthException(resp.ErrorCode);
                    }

                case NtStatus.NtStatusPathNotCovered:
                    {
                        if (req.Auth == null)
                        {
                            throw new SmbException(resp.ErrorCode, null);
                        }
                        DfsReferral? dr = GetDfsReferrals(req.Auth, req.Path, 1);
                        if (dr == null)
                        {
                            throw new SmbException(resp.ErrorCode, null);
                        }
                        SmbFile.Dfs.Insert(req.Path, dr);
                        throw dr;
                    }

                case unchecked((int)(0x80000005)):
                    {
                        break;
                    }

                case NtStatus.NtStatusMoreProcessingRequired:
                    {
                        break;
                    }

                default:
                    {
                        throw new SmbException(resp.ErrorCode, null);
                    }
            }
            if (resp.VerifyFailed)
            {
                throw new SmbException("Signature verification failed.");
            }
        }

        /// <exception cref="SharpCifs.Smb.SmbException"></exception>
        internal virtual void Send(ServerMessageBlock request, ServerMessageBlock response)
        {
            Connect();
            request.Flags2 |= Flags2;
            request.UseUnicode = _useUnicode;
            request.Response = response;
            if (request.Digest == null)
            {
                request.Digest = Digest;
            }
            try
            {
                if (response == null)
                {
                    DoSend0(request);
                    return;
                }
                if (request is SmbComTransaction)
                {
                    response.Command = request.Command;
                    SmbComTransaction req = (SmbComTransaction)request;
                    SmbComTransactionResponse resp = (SmbComTransactionResponse)response;
                    req.MaxBufferSize = SndBufSize;
                    resp.Reset();
                    try
                    {
                        BufferCache.GetBuffers(req, resp);
                        req.Current();
                        if (req.MoveNext())
                        {
                            SmbComBlankResponse interim = new SmbComBlankResponse();
                            Sendrecv(req, interim, SmbConstants.ResponseTimeout);
                            if (interim.ErrorCode != 0)
                            {
                                CheckStatus(req, interim);
                            }
                            req.Current();
                        }
                        else
                        {
                            MakeKey(req);
                        }
                        lock (this)
                        {
                            response.Received = false;
                            resp.IsReceived = false;
                            try
                            {
                                _responseMap.Put(req, resp);
                                do
                                {
                                    DoSend0(req);
                                }
                                while (req.MoveNext() && req.Current() != null);
                                long timeout = SmbConstants.ResponseTimeout;
                                resp.Expiration = Runtime.CurrentTimeMillis() + timeout;
                                while (resp.MoveNext())
                                {
                                    Runtime.Wait(this, timeout);
                                    timeout = resp.Expiration - Runtime.CurrentTimeMillis();
                                    if (timeout <= 0)
                                    {
                                        throw new TransportException(
                                            this + " timedout waiting for response to " + req);
                                    }
                                }
                                if (response.ErrorCode != 0)
                                {
                                    CheckStatus(req, resp);
                                }
                            }
                            catch (Exception ie)
                            {
                                if (ie is SmbException)
                                {
                                    throw;
                                }
                                else
                                {
                                    throw new TransportException(ie);
                                }
                            }
                            finally
                            {
                                //Sharpen.Collections.Remove<Hashtable, SmbComTransaction>(response_map, req);
                                _responseMap.Remove(req);
                            }
                        }
                    }
                    finally
                    {
                        BufferCache.ReleaseBuffer(req.TxnBuf);
                        BufferCache.ReleaseBuffer(resp.TxnBuf);
                    }
                }
                else
                {
                    response.Command = request.Command;
                    Sendrecv(request, response, SmbConstants.ResponseTimeout);
                }
            }
            catch (SmbException)
            {
                throw;
            }
            catch (IOException ioe)
            {
                throw new SmbException(ioe.Message, ioe);
            }
            CheckStatus(request, response);
        }

        public override string ToString()
        {
            return base.ToString() + "[" + _address + ":" + _port + "]";
        }

        internal virtual void DfsPathSplit(string path, string[] result)
        {
            int ri = 0;
            int rlast = result.Length - 1;
            int i = 0;
            int b = 0;
            int len = path.Length;
            do
            {
                if (ri == rlast)
                {
                    result[rlast] = Runtime.Substring(path, b);
                    return;
                }
                if (i == len || path[i] == '\\')
                {
                    result[ri++] = Runtime.Substring(path, b, i);
                    b = i + 1;
                }
            }
            while (i++ < len);
            while (ri < result.Length)
            {
                result[ri++] = string.Empty;
            }
        }

        /// <exception cref="SharpCifs.Smb.SmbException"></exception>
        internal virtual DfsReferral? GetDfsReferrals(NtlmPasswordAuthentication auth,
                                                     string path,
                                                     int rn)
        {
            SmbTree ipc = GetSmbSession(auth).GetSmbTree("IPC$", null);
            Trans2GetDfsReferralResponse resp = new Trans2GetDfsReferralResponse();
            ipc.Send(new Trans2GetDfsReferral(path), resp);
            if (resp.NumReferrals == 0)
            {
                return null;
            }
            if (rn == 0 || resp.NumReferrals < rn)
            {
                rn = resp.NumReferrals;
            }
            DfsReferral dr = new DfsReferral();
            string[] arr = new string[4];
            long expiration = Runtime.CurrentTimeMillis() + Dfs.Ttl * 1000;
            int di = 0;
            for (;;)
            {
                dr.ResolveHashes = auth.HashesExternal;
                dr.Ttl = resp.Referrals[di].Ttl;
                dr.Expiration = expiration;
                if (path.Equals(string.Empty))
                {
                    dr.Server = Runtime.Substring(resp.Referrals[di].Path, 1).ToLower();
                }
                else
                {
                    DfsPathSplit(resp.Referrals[di].Node, arr);
                    dr.Server = arr[1];
                    dr.Share = arr[2];
                    dr.Path = arr[3];
                }
                dr.PathConsumed = resp.PathConsumed;
                di++;
                if (di == rn)
                {
                    break;
                }
                dr.Append(new DfsReferral());
                dr = dr.Next;
            }
            return dr.Next;
        }

        /// <exception cref="SharpCifs.Smb.SmbException"></exception>
        internal virtual DfsReferral[] __getDfsReferrals(NtlmPasswordAuthentication auth,
                                                         string path,
                                                         int rn)
        {
            SmbTree ipc = GetSmbSession(auth).GetSmbTree("IPC$", null);
            Trans2GetDfsReferralResponse resp = new Trans2GetDfsReferralResponse();
            ipc.Send(new Trans2GetDfsReferral(path), resp);
            if (rn == 0 || resp.NumReferrals < rn)
            {
                rn = resp.NumReferrals;
            }
            DfsReferral[] drs = new DfsReferral[rn];
            string[] arr = new string[4];
            long expiration = Runtime.CurrentTimeMillis() + Dfs.Ttl * 1000;
            for (int di = 0; di < drs.Length; di++)
            {
                DfsReferral dr = new DfsReferral();
                dr.ResolveHashes = auth.HashesExternal;
                dr.Ttl = resp.Referrals[di].Ttl;
                dr.Expiration = expiration;
                if (path.Equals(string.Empty))
                {
                    dr.Server = Runtime.Substring(resp.Referrals[di].Path, 1).ToLower();
                }
                else
                {
                    DfsPathSplit(resp.Referrals[di].Node, arr);
                    dr.Server = arr[1];
                    dr.Share = arr[2];
                    dr.Path = arr[3];
                }
                dr.PathConsumed = resp.PathConsumed;
                drs[di] = dr;
            }
            return drs;
        }
    }
}
