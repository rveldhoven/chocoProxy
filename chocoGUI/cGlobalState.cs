using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

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

    public class cUDPStream
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

    public class cPythonScript
    {
        public string script { get; set; }
        public string direction { get; set; }
    }

    static class cGlobalState
    {
        private static object           _tcp_streams_mutex = new object();
        private static List<cTCPStream> _tcp_streams = new List<cTCPStream>();

        private static object _udp_streams_mutex = new object();
        private static List<cUDPStream> _udp_streams = new List<cUDPStream>();

        private static object _proxy_process_mutex = new object();
        private static List<cProxyProcess> _proxy_process_list = new List<cProxyProcess>();

        // TODO: refactor this object in a class.
        private static object _script_list_mutex = new object();
        private static Dictionary<string, Dictionary<string, Dictionary<string, cPythonScript>>> _script_list = new Dictionary<string, Dictionary<string, Dictionary<string, cPythonScript>>>();

        private static Thread _background_thread;
        private static bool _background_is_running = false;
        public static bool global_intercept_flag = false;

        #region background helpers

        private static string send_and_receive_command(cProxyProcess client, string command)
        {
            byte[] receive_buffer = new byte[10 * 65535];
            List<byte> receive_buffer_final = new List<byte>();

            byte[] receive_command_size = new byte[4];

            client.proxy_management_stream.Client.Send(Encoding.UTF8.GetBytes(command));
            client.proxy_management_stream.Client.Receive(receive_command_size);

            int expected_command_size = BitConverter.ToInt32(receive_command_size, 0);
            int received_bytes = 0;

            receive_buffer_final.Clear();

            while (received_bytes < expected_command_size)
            {
                int received_t = client.proxy_management_stream.Client.Receive(receive_buffer);
                receive_buffer_final.AddRange(receive_buffer.Take(received_t));
                received_bytes += received_t;
            }

            string string_received = Encoding.UTF8.GetString(receive_buffer_final.ToArray());

            return string_received;
        }

        private static void send_command(cProxyProcess client, string command)
        {
            client.proxy_management_stream.Client.Send(Encoding.UTF8.GetBytes(command));
        }

        private static string stream_id_to_proxy_id(string stream_id)
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
                throw new Exception("Error: stream_id is no longer linked to proxy");

            List<cProxyProcess> proxy_processes = ui_proxy_process_get();

            foreach (var proxy_process in proxy_processes)
            {
                if (proxy_process.proxy_process_metadata == proxy_management_parent)
                {
                    return proxy_process.proxy_name;
                }
            }

            throw new Exception("Error: stream_id is no longer linked to proxy");
        }

        #endregion

        #region background setters
        
        private static void background_update_tcp_streams()
        {
            cCommand active_streams_struct = new cCommand
            {
                command = "active_streams",
                parameters = new List<List<byte>>(),
            };

            string active_streams_command = JsonConvert.SerializeObject(active_streams_struct);

            lock (_tcp_streams_mutex)
            {
                _tcp_streams.Clear();
            }

            List<cProxyProcess> proxy_list = ui_proxy_process_get();

            foreach (var proxy in proxy_list)
            {
                string string_received = send_and_receive_command(proxy, active_streams_command);

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

        private static void background_update_udp_streams()
        {
            cCommand active_streams_struct = new cCommand
            {
                command = "active_udp_streams",
                parameters = new List<List<byte>>(),
            };

            string active_streams_command = JsonConvert.SerializeObject(active_streams_struct);

            lock (_udp_streams_mutex)
            {
                _udp_streams.Clear();
            }

            List<cProxyProcess> proxy_list = ui_proxy_process_get();

            foreach (var proxy in proxy_list)
            {
                string string_received = send_and_receive_command(proxy, active_streams_command);

                try
                {
                    List<cUDPStream> udp_streams = JsonConvert.DeserializeObject<List<cUDPStream>>(string_received);

                    for (int i = 0; i < udp_streams.Count; i++)
                        udp_streams[i].source_process_name = proxy.proxy_process_metadata;

                    lock (_udp_streams_mutex)
                    {
                        _udp_streams.AddRange(udp_streams);
                    }
                }
                catch (Exception e)
                {
                    continue;
                }
            }
        }

        private static void background_update_scripts()
        {
            cCommand scripts_struct = new cCommand
            {
                command = "active_scripts",
                parameters = new List<List<byte>>(),
            };

            string scripts_command = JsonConvert.SerializeObject(scripts_struct);

            List<cProxyProcess> proxy_list = ui_proxy_process_get();

            foreach (var proxy in proxy_list)
            {
                string string_received = send_and_receive_command(proxy, scripts_command);

                try
                {
                    Dictionary<string, Dictionary<string, cPythonScript>> scripts = JsonConvert.DeserializeObject<Dictionary<string, Dictionary<string, cPythonScript>>>(string_received);

                    lock (_script_list_mutex)
                    {
                        _script_list[proxy.proxy_name] = scripts;
                    }
                }
                catch (Exception e)
                {
                    continue;
                }
            }
        }

        private static void background_main()
        {
            int tcp_stream_update_counter = 0;
            int udp_stream_update_counter = 3;
            int scripts_update_counter = 5;
            int proxy_process_update_counter = 0;

            while (_background_is_running == true)
            {
                // Updates the view on TCP streams
                if (tcp_stream_update_counter++ > 10)
                {
                    tcp_stream_update_counter = 0;

                    background_update_tcp_streams();
                }

                if (udp_stream_update_counter++ > 10)
                {
                    udp_stream_update_counter = 0;

                    background_update_udp_streams();
                }

                if (scripts_update_counter++ > 10)
                {
                    scripts_update_counter = 0;

                    background_update_scripts();
                }

                // Updates the view on running proxies
                if(proxy_process_update_counter++ > 5)
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

        public static bool IsWin64Emulator(this Process process)
        {
            try
            {
                if ((Environment.OSVersion.Version.Major > 5)
                    || ((Environment.OSVersion.Version.Major == 5) && (Environment.OSVersion.Version.Minor >= 1)))
                {
                    bool retVal;
                    return NativeMethods.IsWow64Process(process.Handle, out retVal) && retVal;
                }
                return false; // not on 64-bit Windows Emulator
            }
            catch (Exception e)
            {
                return false;
            }
        }

        internal static class NativeMethods
        {
            [DllImport("kernel32.dll", SetLastError = true, CallingConvention = CallingConvention.Winapi)]
            [return: MarshalAs(UnmanagedType.Bool)]
            internal static extern bool IsWow64Process([In] IntPtr process, [Out] out bool wow64Process);
        }

        public static List<cTCPStream> ui_tcp_streams_get()
        {
            List<cTCPStream> result = new List<cTCPStream>();

            lock (_tcp_streams_mutex)
            {
                result.AddRange(_tcp_streams);
            }

            return result;
        }

        public static List<cUDPStream> ui_udp_streams_get()
        {
            List<cUDPStream> result = new List<cUDPStream>();

            lock (_udp_streams_mutex)
            {
                result.AddRange(_udp_streams);
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

        public static Dictionary<string, Dictionary<string, cPythonScript>> ui_scripts_scripts_get(string proxy_id)
        {
            lock (_script_list_mutex)
            {
                return _script_list[proxy_id];
            }
        }

        #endregion

        #region UI setters

        public static bool ui_proxy_process_start(string metadata, string ip, string port, string u_ip, string u_port, string m_ip, string m_port)
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

            new_proxy.StartInfo.Arguments = "--proxy-ip " + ip + " --proxy-port " + port + " --udp-proxy-ip " + u_ip + " --udp-proxy-port " + u_port + " --manager-ip " + m_ip + " --manager-port " + m_port + " --pcap-dir " + pcap_dir;
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

            foreach (var proxy_process in proxy_processes)
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

        public static void ui_toggle_intercept(string stream_id, string true_or_false, string connection_string)
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
                throw new Exception("Error: interception cannot be toggled because the connection is belongs too has closed");

            List<cProxyProcess> proxy_processes = ui_proxy_process_get();

            foreach (var proxy_process in proxy_processes)
            {
                if (proxy_process.proxy_process_metadata == proxy_management_parent)
                {
                    byte[] bytes_stream_id = Encoding.UTF8.GetBytes(stream_id);
                    byte[] true_bytes_id = Encoding.UTF8.GetBytes(true_or_false);
                    byte[] bytes_connection_string = Encoding.UTF8.GetBytes(connection_string);

                    List<List<byte>> command_parameters = new List<List<byte>>();

                    command_parameters.Add(bytes_stream_id.ToList());
                    command_parameters.Add(true_bytes_id.ToList());
                    command_parameters.Add(bytes_connection_string.ToList());

                    cCommand intercept_stream_command = new cCommand
                    {
                        command = "toggle_intercept",
                        parameters = command_parameters,
                    };

                    string json_command = JsonConvert.SerializeObject(intercept_stream_command);

                    lock (_proxy_process_mutex)
                    {
                        proxy_process.proxy_management_stream.Client.Send(Encoding.UTF8.GetBytes(json_command));
                    }

                    return;
                }
            }

            throw new Exception("Error: interception cannot be toggled because the connection is belongs too has closed");
        }
        
        public static void ui_toggle_global_intercept()
        {
            string toggle = cGlobalState.global_intercept_flag == true ? "true" : "false";

            byte[] bytes_toggle = Encoding.UTF8.GetBytes(toggle);
            List<List<byte>> command_parameters = new List<List<byte>>();
            command_parameters.Add(bytes_toggle.ToList());

            cCommand toggle_global_intercept_command = new cCommand
            {
                command = "global_intercept",
                parameters = command_parameters,
            };

            string string_toggle_intercept_command = JsonConvert.SerializeObject(toggle_global_intercept_command);

            lock (_proxy_process_mutex)
            {
                foreach (cProxyProcess process in _proxy_process_list)
                {
                    process.proxy_management_stream.Client.Send(Encoding.UTF8.GetBytes(string_toggle_intercept_command));
                }
            }
        }

        public static void ui_script_delete_script(string proxy_id, string stream_id, string script_name)
        {
            List<cProxyProcess> proxy_processes = ui_proxy_process_get();

            foreach (var proxy_process in proxy_processes)
            {
                if (proxy_process.proxy_name == proxy_id)
                {
                    byte[] bytes_stream_name = Encoding.UTF8.GetBytes("Global");
                    byte[] bytes_script_name = Encoding.UTF8.GetBytes(script_name);

                    List<List<byte>> delete_parameters = new List<List<byte>>();

                    delete_parameters.Add(bytes_stream_name.ToList());
                    delete_parameters.Add(bytes_script_name.ToList());

                    cCommand delete_script_command = new cCommand
                    {
                        command = "delete_script",
                        parameters = delete_parameters,
                    };

                    string string_delete_command = JsonConvert.SerializeObject(delete_script_command);

                    lock (_proxy_process_mutex)
                    {
                        proxy_process.proxy_management_stream.Client.Send(Encoding.UTF8.GetBytes(string_delete_command));
                    }

                    return;
                }
            }

            throw new Exception("Error: script can't be loaded because the proxy process was not found");
        }

        public static void ui_script_add_script(string proxy_id, string stream_id, string script_name, string script_direction, string script_contents)
        {
            List<cProxyProcess> proxy_processes = ui_proxy_process_get();

            foreach (var proxy_process in proxy_processes)
            {
                if (proxy_process.proxy_name == proxy_id)
                {
                    byte[] bytes_stream_name = Encoding.UTF8.GetBytes("Global");
                    byte[] bytes_script_name = Encoding.UTF8.GetBytes(script_name);
                    byte[] bytes_script_direction = Encoding.UTF8.GetBytes(script_direction);
                    byte[] bytes_script_contents = Encoding.UTF8.GetBytes(script_contents);

                    List<List<byte>> insert_parameters = new List<List<byte>>();

                    insert_parameters.Add(bytes_stream_name.ToList());
                    insert_parameters.Add(bytes_script_name.ToList());
                    insert_parameters.Add(bytes_script_direction.ToList());
                    insert_parameters.Add(bytes_script_contents.ToList());

                    cCommand insert_script_command = new cCommand
                    {
                        command = "insert_script",
                        parameters = insert_parameters,
                    };

                    string string_insert_command = JsonConvert.SerializeObject(insert_script_command);

                    lock (_proxy_process_mutex)
                    {
                        proxy_process.proxy_management_stream.Client.Send(Encoding.UTF8.GetBytes(string_insert_command));
                    }

                    return;
                }
            }

            throw new Exception("Error: script can't be loaded because the proxy process was not found");
        }


        #endregion
    }
}

