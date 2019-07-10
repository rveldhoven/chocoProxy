using System;
using System.Collections.Generic;
using System.Linq;
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
        public string destination_ip{ get; set; }
        public string source_port{ get; set; }
        public string destination_port{ get; set; }
        public string backend_file{ get; set; }
        public bool proxy_connected { get; set; }
        public string stream_start { get; set; }
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
                    backend_file = "127_0_0_1_2525_127_0_0_1_4454_201907100039.pcap",
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

            while (_background_is_running == true)
            {
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

