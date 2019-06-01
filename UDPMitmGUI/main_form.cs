using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Windows.Forms;

namespace UDPMitmGUI
{
    public partial class main_form : Form
    {


        private Be.Windows.Forms.HexBox _my_hex_box; 
        private bool _is_intercepting = false;
        private TcpListener _mitm_listener = new TcpListener(IPAddress.Parse("127.0.0.1"), 3456);
        private List<cMITMSession> _mitm_sessions = new List<cMITMSession>();

        private Timer _server_timer = new Timer();
        private object _traffic_mutex = new object ();
        private bool _is_parsing_udp = false;
        private string current_session_id = "";

        private bool toggle_session_intercept(string session_id)
        {
            foreach (cMITMSession mitm_object in _mitm_sessions)
            {
                if(mitm_object.get_mitm_id() == session_id)
                {
                    mitm_object._is_intercepting = !mitm_object._is_intercepting;

                    if (mitm_object._is_intercepting == true)
                        current_session_id = session_id;

                    return mitm_object._is_intercepting;
                }
            }

            return false;
        }

        private byte[] get_bytes_from_session(string session_id)
        {
            foreach (cMITMSession mitm_object in _mitm_sessions)
            {
                if (mitm_object.get_mitm_id() == session_id)
                {
                    if (mitm_object._is_intercepting == false)
                        return new byte[0];

                    return mitm_object.get_mitm_bytes().ToArray();
                }
            }

            return new byte[0];
        }

        private void send_bytes_to_session(string session_id, byte[] bytes)
        {
            foreach (cMITMSession mitm_object in _mitm_sessions)
            {
                if (mitm_object.get_mitm_id() == session_id)
                {
                    if (mitm_object._is_intercepting == false)
                        return;

                    mitm_object.send_mitm_bytes(bytes.ToList());
                }
            }
        }

        private void set_session_intercept(string session_id, bool value)
        {
            foreach (cMITMSession mitm_object in _mitm_sessions)
            {
                if (mitm_object.get_mitm_id() == session_id)
                {
                    mitm_object._is_intercepting = value;

                    return;
                }
            }

            return;
        }

        public main_form()
        {
            InitializeComponent();
            _my_hex_box = new Be.Windows.Forms.HexBox { Dock = DockStyle.Fill };
            _my_hex_box.StringViewVisible = true;

            mitm_main_window.Controls.Add(_my_hex_box);
            _mitm_listener.Start();

            _server_timer.Interval = 10;
            _server_timer.Tick += timer_tick;
            _server_timer.Start();
        }

        private void handle_connecting_client()
        {
            while(_mitm_listener.Pending() == true)
                _mitm_sessions.Add(new cMITMSession(_mitm_listener.AcceptTcpClient()));
        }

        private void handle_client_traffic()
        {
            return;
        }

        private void handle_client_echo()
        {
            return;
        }

        private void handle_current_client()
        {
            if (_is_intercepting == false)
                return;

            if (_is_parsing_udp == true)
                return;

            if (current_session_id == "")
                return;

            var bytes = get_bytes_from_session(current_session_id);

            if (bytes.Length == 0)
                return;

            _my_hex_box.ByteProvider = new Be.Windows.Forms.DynamicByteProvider(bytes);
            _my_hex_box.StringViewVisible = true;

           _is_parsing_udp = true;
        }

        private void timer_tick(object sender, EventArgs e)
        {
            if(_is_intercepting == true)
                label2.Text = "true";
            else
                label2.Text = "false";

            List<string> mitm_names = new List<string>();

            bool invalidate = false;

            foreach (var mitm_connection in _mitm_sessions)
            {
                string mitm_id = mitm_connection.get_mitm_id();

                if (mitm_connection.is_running() == false)
                    continue;

                mitm_names.Add(mitm_id);

                if (mitm_sessions.Items.Contains(mitm_id) == true)
                    continue;

                invalidate = true;
            }

            if(invalidate == false)
            {
                foreach (string mitm_connection in mitm_sessions.Items)
                {
                    string mitm_id = mitm_connection;

                    if (mitm_names.Contains(mitm_id) == true)
                        continue;

                    invalidate = true;
                }
            }

            if (invalidate == true)
            {
                mitm_sessions.Items.Clear();
                mitm_sessions.Items.AddRange(mitm_names.ToArray());
            }

            handle_connecting_client();

            handle_current_client();
        }

        private void label1_Click(object sender, EventArgs e)
        {

        }

        private void Form1_Load(object sender, EventArgs e)
        {

        }

        private void send_button_Click(object sender, EventArgs e)
        {
            if(_my_hex_box == null)
            {
                _is_parsing_udp = false;
                return;
            }

            if(_my_hex_box.ByteProvider == null)
            {
                _is_parsing_udp = false;
                return;
            }

            if (_my_hex_box.ByteProvider.Length == 0)
            {
                _is_parsing_udp = false;
                return;
            }

            List<byte> send_bytes = new List<byte>();

            for (uint i = 0; i < _my_hex_box.ByteProvider.Length; i++)
                send_bytes.Add(_my_hex_box.ByteProvider.ReadByte(i));
 
            _my_hex_box.ByteProvider.DeleteBytes(0, _my_hex_box.ByteProvider.Length);
            _my_hex_box.ByteProvider = null;

            send_bytes_to_session(current_session_id, send_bytes.ToArray());

            _is_parsing_udp = false;
        }

        private void intercept_button_Click(object sender, EventArgs e)
        {
            if (mitm_sessions.SelectedIndex == -1)
            {
                _is_intercepting = false;
                return;
            }

            current_session_id = (string)mitm_sessions.Items[mitm_sessions.SelectedIndex];

            if (_is_intercepting == true)
            {
                _is_intercepting = false;

                send_button_Click(sender, e);

                set_session_intercept(current_session_id, false);
            }
            else
            {
                _is_intercepting = true;
                set_session_intercept(current_session_id, true);
            }
        }

        private void button1_Click(object sender, EventArgs e)
        {
            var test_form = new inject_form();

            test_form.ShowDialog();

            if (test_form.stop_clicked == true)
                return;

            if (test_form.do_inject_elevated == true)
                Process.EnterDebugMode();

            string pid = test_form.pid;
            string injector_path = "chocoInjector";
            string dll_path = "chocoDLL";

            int real_pid = int.Parse(pid);

            Process target_process = Process.GetProcessById(real_pid);

            if (cNativeMethods.is_process_64_bit(target_process) == true)
            {
                injector_path += "64";
                dll_path += "64";
            }

            injector_path += ".exe";
            dll_path += ".dll";

            string real_injector_path = Path.Combine(System.Environment.CurrentDirectory, injector_path);
            string real_dll_path = Path.Combine(System.Environment.CurrentDirectory, dll_path);

            string hooked_function = "";

            if (test_form.do_mitm_udp == true)
                hooked_function = "sendto";
            else
                hooked_function = "send";

            ProcessStartInfo startup_info = new ProcessStartInfo();

            if (test_form.do_inject_elevated == true)
            {
                startup_info.UseShellExecute = true;
                startup_info.Verb = "runas";
            }

            startup_info.FileName = real_injector_path;
            startup_info.Arguments = pid.ToString() + " \"" + real_dll_path + "\" 127.0.0.1 3456 " + hooked_function;

            Process.Start(startup_info);

            if (test_form.do_inject_elevated == true)
                Process.LeaveDebugMode();
        }

        private void mitm_sessions_Click(object sender, EventArgs e)
        {
            _is_intercepting = false;

            send_button_Click(sender, e);

            foreach (string object_id in mitm_sessions.Items)
            {
                set_session_intercept(object_id, false);
            }
        }
    }

    public static class cNativeMethods
    {
        [DllImport("kernel32.dll", SetLastError = true, CallingConvention = CallingConvention.Winapi)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool IsWow64Process([In] IntPtr hProcess, [Out] out bool lpSystemInfo);

        public static bool is_process_64_bit(Process checked_process)
        {
            if (Environment.Is64BitOperatingSystem == false)
                return false;

            bool is_32bit_context;

            IsWow64Process(checked_process.Handle, out is_32bit_context);

            return !is_32bit_context;
        }
    }
}
