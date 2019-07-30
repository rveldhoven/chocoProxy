using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace chocoGUI
{
    public class cProxyProcess
    {
        public string proxy_name { get; set; }
        public string proxy_process_metadata { get; set; }
        public string proxy_ip { get; set; }
        public string proxy_port{ get; set; }
        public string management_ip { get; set; }
        public string management_port { get; set; }
        public string pcap_dir { get; set; }
        public Process process_handle { get; set; }
        public TcpClient proxy_management_stream { get; set; }
    }

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

        private static object _proxy_process_mutex = new object();
        private static List<cProxyProcess> _proxy_process_list = new List<cProxyProcess>();

        private static Thread _background_thread;
        private static bool _background_is_running = false;

        #region background setters

        private static void background_main()
        {
            cCommand command = new cCommand
            {
                command = "active_streams",
                parameters = new List<List<byte>>(),
            };

            string json_command = JsonConvert.SerializeObject(command);
            byte[] bytes_command = new byte[10*65535];
            List<byte> bytes_command_appended = new List<byte>();
            byte[] number_of_bytes = new byte[4];
            int tcp_stream_update_counter = 0;
            int proxy_provess_update_counter = 0;

            while (_background_is_running == true)
            {
                // Updates the view on TCP streams
                if (tcp_stream_update_counter++ > 10)
                {
                    lock(_tcp_streams_mutex)
                    {
                        _tcp_streams.Clear();
                    }

                    tcp_stream_update_counter = 0;

                    List<cProxyProcess> proxy_list = ui_proxy_process_get();

                    foreach (var proxy in proxy_list)
                    {
                        proxy.proxy_management_stream.Client.Send(Encoding.UTF8.GetBytes(json_command));
                        proxy.proxy_management_stream.Client.Receive(number_of_bytes);
                        int expect_bytes = BitConverter.ToInt32(number_of_bytes, 0);
                        int received_bytes = 0;

                        bytes_command_appended.Clear();

                        while (received_bytes < expect_bytes)
                        {
                            int received_t = proxy.proxy_management_stream.Client.Receive(bytes_command);
                            bytes_command_appended.AddRange(bytes_command.Take(received_t));
                            received_bytes += received_t;
                        }

                        string string_received = Encoding.UTF8.GetString(bytes_command_appended.ToArray());

                        try
                        {
                            List<cTCPStream> tcp_streams = JsonConvert.DeserializeObject<List<cTCPStream>>(string_received);

                            for (int i = 0; i < tcp_streams.Count; i++)
                                tcp_streams[i].source_process_name = proxy.proxy_process_metadata;

                            lock (_tcp_streams_mutex)
                            {
                                _tcp_streams.AddRange(tcp_streams);
                            }
                        }
                        catch (Exception e)
                        {
                            continue;
                        }
                    }
                }

                // Updates the view on running proxies
                if(proxy_provess_update_counter++ > 5)
                {
                    lock (_proxy_process_mutex)
                    {
                        _proxy_process_list.RemoveAll(delegate (cProxyProcess p) { return p.process_handle.HasExited == true; });
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

            return result;
        }

        public static List<cProxyProcess> ui_proxy_process_get()
        {
            List<cProxyProcess> result = new List<cProxyProcess>();

            lock(_proxy_process_mutex)
            {
                result.AddRange(_proxy_process_list);
            }

            return result;
        }

        #endregion

        #region UI setters

        public static bool ui_proxy_process_start(string metadata, string ip, string port, string m_ip, string m_port)
        {
            bool metadata_unique = false;

            lock (_proxy_process_mutex)
            {
                foreach (cProxyProcess process in _proxy_process_list)
                {
                    if(process.proxy_process_metadata == metadata)
                    {
                        metadata_unique = true;
                        break;
                    }
                }
            }

            if(metadata_unique == true || metadata == "")
            {
                throw new Exception("Error: metadata is not unique, metadata must be set and unique");
            }

            Process new_proxy = new Process();

            string pcap_dir = "proxy_" + ip + "_" + port + "m_" + m_ip + "_" + m_port;

            new_proxy.StartInfo.Arguments = "--proxy-ip " + ip + " --proxy-port " + port + " --manager-ip " + m_ip + " --manager-port " + m_port + " --pcap-dir " + pcap_dir;
            new_proxy.StartInfo.FileName = "chocoSocks.exe";

            bool result = new_proxy.Start();

            if (result == false)
                return result;

            Thread.Sleep(200);

            if (new_proxy.HasExited == true)
                return false;

            TcpClient new_manager = new TcpClient();
            
            try
            {
                new_manager.Connect(m_ip, int.Parse(m_port));
            }
            catch (Exception e)
            {
                return false;
            }

            cProxyProcess proxy_data = new cProxyProcess
            {
                proxy_name = ip + ":" + port,
                proxy_process_metadata = metadata,
                proxy_ip = ip,
                proxy_port = port,
                management_ip = m_ip,
                management_port = m_port,
                pcap_dir = pcap_dir,
                process_handle = new_proxy,
                proxy_management_stream = new_manager,
            };

            lock (_proxy_process_mutex)
            {
                _proxy_process_list.Add(proxy_data);
            }

            return result;
        }

        public static bool ui_proxy_process_stop(string proxy_ip, string proxy_port)
        {
            cProxyProcess process = null;

            lock (_proxy_process_mutex)
            {
                int i = 0;
                bool proxy_found = false;

                for (; i < _proxy_process_list.Count; i++)
                {
                    if (_proxy_process_list[i].proxy_ip == proxy_ip && _proxy_process_list[i].proxy_port == proxy_port)
                    {
                        proxy_found = true;
                        break;
                    }
                }

                if (proxy_found == false)
                    return false;

                process = _proxy_process_list[i];
                _proxy_process_list.RemoveAt(i);
            }

            process.process_handle.Kill();
            process.proxy_management_stream.Close();

            return true;
        }

        public static void ui_proxy_repeat_packet(string stream_id, List<byte> packet_bytes)
        {
            string proxy_management_parent = "";

            List<cTCPStream> tcp_streams = ui_tcp_streams_get();

            foreach (var tcp_stream in tcp_streams)
            {
                if (tcp_stream.stream_start == stream_id)
                {
                    proxy_management_parent = tcp_stream.source_process_name;
                    break;
                }
            }

            if (proxy_management_parent == "")
                throw new Exception("Error: packet can't be repeated because the connection is belongs to has closed");

            List<cProxyProcess> proxy_processes = ui_proxy_process_get();

            foreach(var proxy_process in proxy_processes)
            {
                if (proxy_process.proxy_process_metadata == proxy_management_parent)
                {
                    byte[] bytes_stream_id = Encoding.UTF8.GetBytes(stream_id);

                    List<List<byte>> command_parameters = new List<List<byte>>();

                    command_parameters.Add(bytes_stream_id.ToList());
                    command_parameters.Add(packet_bytes);

                    cCommand repeat_packet_command = new cCommand
                    {
                        command = "repeat_packet",
                        parameters = command_parameters,
                    };

                    string json_command = JsonConvert.SerializeObject(repeat_packet_command);

                    lock (_proxy_process_mutex)
                    {
                        proxy_process.proxy_management_stream.Client.Send(Encoding.UTF8.GetBytes(json_command));
                    }

                    return;
                }
            }

            throw new Exception("Error: packet can't be repeated because the connection is belongs to has closed");
        }

        #endregion

    }
}

