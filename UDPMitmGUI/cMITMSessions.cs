using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Net;
using System.Net.Sockets;
using System.Threading;

namespace UDPMitmGUI
{
    public class cMITMSession
    {
        private static int _global_id = 0;

        private TcpClient _mitm_client;
        private int _mitm_id;

        public bool _is_intercepting = true;
        private bool _is_running = true;
        private Thread _mitm_session_thread;

        private int ping_counter = 0;

        private void handle_echo()
        {
            try
            {
 
                if (ping_counter++ > 0x100)
                {
                    List<byte> ping_buffer = new List<byte>();

                    ping_buffer.Add(0xff);
                    ping_buffer.Add(0xff);
                    ping_buffer.Add(0xff);
                    ping_buffer.Add(0xff);

                    _mitm_client.Client.Send(ping_buffer.ToArray());
                    ping_counter = 0;
                }

                if (_is_intercepting == true)
                    return;

                if (_mitm_client.Client.Available < sizeof(UInt32))
                    return;

                UInt32 size_available = 0;

                byte[] size_avail_bytes = new byte[sizeof(UInt32)];

                _mitm_client.Client.Receive(size_avail_bytes);

                size_available = BitConverter.ToUInt32(size_avail_bytes, 0);

                if (size_available == 0)
                    return;

                byte[] real_byte_buffer = new byte[size_available];
                _mitm_client.Client.Receive(real_byte_buffer);

                List<byte> response_buffer = new List<byte>();

                response_buffer.AddRange(size_avail_bytes);
                response_buffer.AddRange(real_byte_buffer);

                _mitm_client.Client.Send(response_buffer.ToArray());
            }
            catch(Exception e)
            {
                _is_running = false;
                _is_intercepting = false;
            }
        }

        private void mitm_session_main()
        {
            while(_is_running == true)
            {
                handle_echo();

                Thread.Sleep(10);
            }
        }

        public cMITMSession(TcpClient mitm_client)
        {
            _mitm_id = _global_id++;

            _mitm_client = mitm_client;

            _is_running = true;
            _is_intercepting = false;
            _mitm_session_thread = new Thread(() => mitm_session_main());
            _mitm_session_thread.Start();
        }

        ~cMITMSession()
        {
            _is_running = false;
            _mitm_session_thread.Join();
        }

        public bool is_running()
        {
            return _is_running;
        }

        public List<byte> get_mitm_bytes()
        {
            List<byte> result_bytes = new List<byte>();

            if (_is_intercepting == false)
                return result_bytes;

            if (_mitm_client.Client.Available < sizeof(UInt32))
                return result_bytes;

            UInt32 size_available = 0;

            byte[] size_avail_bytes = new byte[sizeof(UInt32)];

            _mitm_client.Client.Receive(size_avail_bytes);

            size_available = BitConverter.ToUInt32(size_avail_bytes, 0);

            if (size_available == 0)
                return result_bytes;

            byte[] real_byte_buffer = new byte[size_available];
            _mitm_client.Client.Receive(real_byte_buffer);

            result_bytes.AddRange(real_byte_buffer);
            return result_bytes;
        }

        public void send_mitm_bytes(List<byte> bytes)
        {
            List<byte> send_buffer = new List<byte>();

            UInt32 send_size = (UInt32) bytes.Count;

            byte[] size_bytes = BitConverter.GetBytes(bytes.Count);

            send_buffer.AddRange(size_bytes);
            send_buffer.AddRange(bytes);

            _mitm_client.Client.Send(send_buffer.ToArray());
        }

        public string get_mitm_id()
        {
            return _mitm_client.Client.LocalEndPoint.ToString() + " id: " + _mitm_id.ToString();
        }
    }
}
