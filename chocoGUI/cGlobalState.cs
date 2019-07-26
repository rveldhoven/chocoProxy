using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace chocoGUI
{
    public class cTCPStream
    {
        public string source_process_pid { get; set; }
        public string source_process_name { get; set; }
        public string source_ip { get; set; }
        public string destination_ip { get; set; }
        public string source_port { get; set; }
        public string destination_port { get; set; }
        public string backend_file { get; set; }
        public bool proxy_connected { get; set; }
        public string stream_start { get; set; }
    }

    public class cCommand
    {
        public string command { get; set; }
        public List<List<byte>> parameters { get; set; }
    }  

    static class cGlobalState
    {
        private static object           _tcp_streams_mutex = new object();
        private static List<cTCPStream> _tcp_streams = new List<cTCPStream>();

        private static Thread _background_thread;
        private static bool _background_is_running = false;

        #region background setters

        private static void background_main()
        {
            lock (_tcp_streams_mutex)
            {
                // Mock result
                _tcp_streams.Add(new cTCPStream
                {
                    source_process_pid = "1337",
                    source_process_name = "firefox.exe",
                    source_ip = "127.0.0.1",
                    destination_ip = "127.0.0.1",
                    source_port = "2525",
                    destination_port = "4454",
                    backend_file = "stream1563975580302.pcap",
                    proxy_connected = false,
                    stream_start = DateTime.Now.ToString(),
                });

                _tcp_streams.Add(new cTCPStream
                {
                    source_process_pid = "1337",
                    source_process_name = "firefox.exe",
                    source_ip = "127.0.0.1",
                    destination_ip = "127.0.0.1",
                    source_port = "2525",
                    destination_port = "4457",
                    backend_file = "127_0_0_1_2525_127_0_0_1_4454_201907100039.pcap",
                    proxy_connected = true,
                    stream_start = DateTime.Now.ToString(),
                });
            }

            TcpClient socket = new TcpClient("127.0.0.1", 81);

            cCommand command = new cCommand
            {
                command = "active_streams",
                parameters = new List<List<byte>>(),
            };

            string json_command = JsonConvert.SerializeObject(command);
            byte[] bytes_command = new byte[10*65535];
            List<byte> bytes_command_appended = new List<byte>();
            byte[] number_of_bytes = new byte[8];
            int counter = 0;

            while (_background_is_running == true)
            {
                if (counter++ > 10)
                {
                    socket.Client.Send(Encoding.UTF8.GetBytes(json_command));
                    Thread.Sleep(100);
                    socket.Client.Receive(number_of_bytes);
                    long expect_bytes = BitConverter.ToInt64(number_of_bytes, 0);
                    long received_bytes = 0;
                    while ( received_bytes < expect_bytes)
                    {
                        int received_t = socket.Client.Receive(bytes_command);
                        bytes_command_appended.AddRange(bytes_command.Take(received_t));
                        received_bytes += received_t;
                    }
                    string string_received = Encoding.UTF8.GetString(bytes_command_appended.ToArray());
                    bytes_command_appended.Clear();
                    counter = 0;
                    try
                    {
                        List<cTCPStream> tcp_stream = JsonConvert.DeserializeObject<List<cTCPStream>>(string_received);
                        lock (_tcp_streams_mutex)
                        {
                            _tcp_streams = tcp_stream;
                        }
                    } 
                    catch(Exception e)
                    {
                        continue;
                    }

                }
                Thread.Sleep(100);
            }
        }

        public static void background_thread_start()
        {
            if (_background_is_running == true)
                throw new Exception("Error: background thread already running");

            _background_is_running = true;

            try
            {
                _background_thread = new Thread(background_main);
                _background_thread.Start();
            }
            catch (Exception e)
            {
                _background_is_running = false;
            }
        }

        public static void background_thread_stop()
        {
            if (_background_is_running == false)
                throw new Exception("Error: background thread not running");

            _background_thread.Join();
        }

        #endregion

        #region UI getters

        public static List<cTCPStream> ui_tcp_streams_get()
        {
            List<cTCPStream> result = new List<cTCPStream>();

            lock (_tcp_streams_mutex)
            {
                result.AddRange(_tcp_streams);
            }

            // Mock results for now

            return result;
        }

        #endregion

    }
}

