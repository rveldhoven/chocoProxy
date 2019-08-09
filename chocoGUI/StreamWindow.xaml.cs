using SharpPcap;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Forms.Integration;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Shapes;
using System.Windows.Threading;

namespace chocoGUI
{
    /// <summary>
    /// Interaction logic for StreamWindow.xaml
    /// </summary>
    public partial class StreamWindow : Window
    {
        private string _stream_type = "";

        private string _backend_file = null;
        private long _backend_size = 0;
        private string _stream_id = "";
        private int _child_id = 0;

        private bool _is_intercepting = false;
        private TcpClient _intercepting_client = new TcpClient();

        private List<List<byte>> _packet_bytes = new List<List<byte>>();

        public DispatcherTimer ui_dispatcher_timer = new DispatcherTimer();

        int tab_counter = 0;

        private TcpClient ui_tcp_wait_for_connection()
        {
            string connection_string = "";

            Random temp_random = new Random();

            while(true)
            {
                try
                {
                    int Port = temp_random.Next(1024, 0xfffe);

                    TcpListener temp_listener = new TcpListener(IPAddress.Loopback, Port);
                    temp_listener.Start();

                    connection_string = "127.0.0.1:" + Port.ToString();

                    cGlobalState.ui_toggle_intercept(_stream_id, "true", connection_string);

                    for(int i = 0; i < 30; i++)
                    {
                        if (temp_listener.Pending() == false)
                        {
                            Thread.Sleep(100);
                            continue;
                        }

                        var temp_stream = temp_listener.AcceptTcpClient();

                        temp_listener.Stop();

                        return temp_stream;

                    }

                    MessageBox.Show("Error: client proxy did not return in time, this could indicate the connection that is being intercepted has closed", "Error", MessageBoxButton.OK, MessageBoxImage.Error);

                    _is_intercepting = false;

                    cGlobalState.ui_toggle_intercept(_stream_id, "false", "127.0.0.1:1231");
                    intercept_status.Content = "Intercepting: " + (_is_intercepting == true ? "yes" : "no");

                    return new TcpClient();
                }
                catch(Exception e)
                {
                }
            }
        }

        private void ui_populate_packet_view()
        {
            // There's a race condition here, but imo not worth changing the architecture to fix yet.
            if (cFileUtilities.get_size(_backend_file) == _backend_size)
                return;

            _backend_size = cFileUtilities.get_size(_backend_file);

            ICaptureDevice pcap_device = null;

            bool has_temp_file_open = false;

            string temp_file = "";

            _packet_bytes.Clear();

            try
            {
                temp_file = cFileUtilities.get_temp_copy(_backend_file);

                has_temp_file_open = true;

                pcap_device = new SharpPcap.LibPcap.CaptureFileReaderDevice(temp_file);
                pcap_device.Open();

                RawCapture capture;
                int current_packet = 0;

                while((capture = pcap_device.GetNextPacket()) != null)
                {
                    var eth_packet = PacketDotNet.Packet.ParsePacket(capture.LinkLayerType, capture.Data);

                    PacketDotNet.IPPacket ip_packet = eth_packet.Extract<PacketDotNet.IPPacket>();
                    if (_stream_type == "tcp")
                    {
                        PacketDotNet.TcpPacket tcp_packet = eth_packet.Extract<PacketDotNet.TcpPacket>();
                        _packet_bytes.Add(tcp_packet.PayloadData.ToList());

                        object packet_view_item = new
                        {
                            PacketNumber = current_packet.ToString(),
                            Source = ip_packet.SourceAddress.ToString() + ":" + tcp_packet.SourcePort.ToString(),
                            Destination = ip_packet.DestinationAddress.ToString() + ":" + tcp_packet.DestinationPort.ToString(),
                            PayloadLength = tcp_packet.PayloadData.Length.ToString(),
                        };

                        if (packet_stream_view.Items.Contains(packet_view_item) == false)
                            packet_stream_view.Items.Add(packet_view_item);
                    }
                    else
                    {
                        PacketDotNet.UdpPacket udp_packet = eth_packet.Extract<PacketDotNet.UdpPacket>();
                        _packet_bytes.Add(udp_packet.PayloadData.ToList());

                        object packet_view_item = new
                        {
                            PacketNumber = current_packet.ToString(),
                            Source = ip_packet.SourceAddress.ToString() + ":" + udp_packet.SourcePort.ToString(),
                            Destination = ip_packet.DestinationAddress.ToString() + ":" + udp_packet.DestinationPort.ToString(),
                            PayloadLength = udp_packet.PayloadData.Length.ToString(),
                        };

                        if (packet_stream_view.Items.Contains(packet_view_item) == false)
                            packet_stream_view.Items.Add(packet_view_item);
                    }

                    current_packet++;
                }
            }
            catch(Exception e)
            {
                if (has_temp_file_open == true)
                {
                    cFileUtilities.remove_temp_copy(temp_file);
                    has_temp_file_open = false;
                }

                MessageBox.Show("Error: " + e.Message, "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }

            if(pcap_device != null)
                pcap_device.Close();

            if (has_temp_file_open == true)
            {
                cFileUtilities.remove_temp_copy(temp_file);
                has_temp_file_open = false;
            }
        }

        private List<byte> ui_receive_intercepted_packet()
        {
            byte[] receive_buffer = new byte[10 * 65535];
            List<byte> receive_buffer_final = new List<byte>();

            byte[] receive_command_size = new byte[4];

            _intercepting_client.Client.Receive(receive_command_size);

            int expected_command_size = BitConverter.ToInt32(receive_command_size, 0);
            int received_bytes = 0;

            receive_buffer_final.Clear();

            while (received_bytes < expected_command_size)
            {
                int received_t = _intercepting_client.Client.Receive(receive_buffer);
                receive_buffer_final.AddRange(receive_buffer.Take(received_t));
                received_bytes += received_t;
            }

            return receive_buffer_final;
        }

        private void ui_send_intercepted_packet(List<byte> packet)
        {
            if (_is_intercepting == false)
                return;

            _intercepting_client.Client.Send(BitConverter.GetBytes((UInt32)packet.Count));
            _intercepting_client.Client.Send(packet.ToArray());
        }
        
        private void send_packet_button_Click(object sender, RoutedEventArgs e)
        {
            if (_is_intercepting == false)
                return;

            if (selected_packet_status.Content.ToString() != "INTERCEPTED PACKET (READ+WRITE)")
            {
                MessageBox.Show("Warning: The selected paket is an old packet, it cannot be sent now", "Warning", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            System.Windows.Forms.Integration.WindowsFormsHost host = (WindowsFormsHost)grid1.Children[_child_id];

            Be.Windows.Forms.HexBox my_hex_box = (Be.Windows.Forms.HexBox)host.Child;

            List<byte> send_bytes = new List<byte>();

            for (uint i = 0; i < my_hex_box.ByteProvider.Length; i++)
                send_bytes.Add(my_hex_box.ByteProvider.ReadByte(i));

            my_hex_box.ByteProvider = new Be.Windows.Forms.DynamicByteProvider(new List<byte>());
            my_hex_box.ReadOnly = true;

            ui_send_intercepted_packet(send_bytes);

            selected_packet_status.Content = "NO PACKET (READONLY)";
        }

        private void ui_handle_intercept()
        {
            if (_is_intercepting == false)
                return;

            System.Windows.Forms.Integration.WindowsFormsHost host = (WindowsFormsHost)grid1.Children[_child_id];

            Be.Windows.Forms.HexBox my_hex_box = (Be.Windows.Forms.HexBox)host.Child;

            if (_intercepting_client.Client.Available < 4)
                return;

            selected_packet_status.Content = "INTERCEPTED PACKET (READ+WRITE)";

            List<byte> new_bytes = ui_receive_intercepted_packet();

            my_hex_box.ByteProvider = new Be.Windows.Forms.DynamicByteProvider(new_bytes);
            my_hex_box.StringViewVisible = true;
            my_hex_box.VScrollBarVisible = true;
            my_hex_box.ReadOnly = false;
        }

        private void ui_update_tick(object sender, EventArgs e)
        {
            ui_populate_packet_view();

            ui_handle_intercept();
        }

        public StreamWindow(string backend_file, string stream_id, string stream_type)
        {
            InitializeComponent();

            _stream_type = stream_type;

            _stream_id = stream_id;

            var gridView = new GridView();

            gridView.Columns.Add(new GridViewColumn() { Header = "Packet no.", DisplayMemberBinding = new Binding("PacketNumber") });
            gridView.Columns.Add(new GridViewColumn() { Header = "Source", DisplayMemberBinding = new Binding("Source") });
            gridView.Columns.Add(new GridViewColumn() { Header = "Destination", DisplayMemberBinding = new Binding("Destination") });
            gridView.Columns.Add(new GridViewColumn() { Header = "Payload Length", DisplayMemberBinding = new Binding("PayloadLength") });

            packet_stream_view.View = gridView;

            //packet_hex_editor.ReadOnlyMode = true;

            _backend_file = backend_file;

            System.Windows.Forms.Integration.WindowsFormsHost host = new System.Windows.Forms.Integration.WindowsFormsHost();

            var hex_box = new Be.Windows.Forms.HexBox { Dock = System.Windows.Forms.DockStyle.Fill };

            host.Child = hex_box;

            Grid.SetRow(host, 1);

            _child_id = grid1.Children.Add(host);

            hex_box.ByteProvider = new Be.Windows.Forms.DynamicByteProvider(new List<byte>());
            hex_box.ReadOnly = true;

            selected_packet_status.Content = "NO PACKET (READONLY)";

            ui_dispatcher_timer.Tick += new EventHandler(ui_update_tick);
            ui_dispatcher_timer.Interval = new TimeSpan(0, 0, 0, 0, 500);
            ui_dispatcher_timer.Start();

            if (cGlobalState.global_intercept_flag == true)
            {
                _is_intercepting = true;

                intercept_status.Content = "Intercepting: " + (_is_intercepting == true ? "yes" : "no");

                _intercepting_client = ui_tcp_wait_for_connection();
            }
        }

        private void SendToRepeater_Click(object sender, RoutedEventArgs e)
        {
            if (_stream_type != "tcp")
            {
                MessageBox.Show("Warning: UDP repeating is not yet supported", "Warning", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            var packet_display_object = packet_stream_view.SelectedItem;

            if ((string)object_helper.get_object_value(packet_display_object, "PayloadLength") == "0")
                return;

            int packet_number = int.Parse((string)object_helper.get_object_value(packet_display_object, "PacketNumber"));

            List<byte> packet_bytes = _packet_bytes[packet_number];

            System.Windows.Forms.Integration.WindowsFormsHost host = new System.Windows.Forms.Integration.WindowsFormsHost();
            var hex_box = new Be.Windows.Forms.HexBox { Dock = System.Windows.Forms.DockStyle.Fill };
            host.Child = hex_box;

            Grid repeater_tab_grid = new Grid();
            repeater_tab_grid.HorizontalAlignment = HorizontalAlignment.Stretch;
            repeater_tab_grid.VerticalAlignment = VerticalAlignment.Stretch;

            RowDefinition row_one = new RowDefinition();
            RowDefinition row_two = new RowDefinition();

            row_one.Height = new GridLength(80, GridUnitType.Star);
            row_two.Height = new GridLength(20, GridUnitType.Star);

            repeater_tab_grid.RowDefinitions.Add(row_one);
            repeater_tab_grid.RowDefinitions.Add(row_two);

            Button send_button = new Button();

            send_button.Content = "Send packet";
            send_button.HorizontalAlignment = HorizontalAlignment.Left;
            send_button.VerticalAlignment = VerticalAlignment.Stretch;


            hex_box.ByteProvider = new Be.Windows.Forms.DynamicByteProvider(packet_bytes);
            hex_box.StringViewVisible = true;
            hex_box.VScrollBarVisible = true;

            send_button.Click += new RoutedEventHandler(delegate (object inner_sender, RoutedEventArgs inner_e)
            {
                List<byte> send_bytes = new List<byte>();

                for (uint i = 0; i < hex_box.ByteProvider.Length; i++)
                    send_bytes.Add(hex_box.ByteProvider.ReadByte(i));

                cGlobalState.ui_proxy_repeat_packet(_stream_id, send_bytes);
            });

            Grid.SetRow(send_button, 1);
            Grid.SetRow(host, 0);

            repeater_tab_grid.Children.Add(host);
            repeater_tab_grid.Children.Add(send_button);

            TabItem new_tab = new TabItem();
            new_tab.Header = "Repeater_" + packet_number.ToString() + "_" + (tab_counter++).ToString();
            new_tab.Content = repeater_tab_grid;

            repeater_tab.Items.Add(new_tab);
        }

        private void Packet_stream_view_MouseUp(object sender, MouseButtonEventArgs e)
        {
            if (packet_stream_view.SelectedIndex == -1)
                return;

            if (selected_packet_status.Content.ToString() == "INTERCEPTED PACKET (READ+WRITE)")
            {
                MessageBox.Show("Warning: first send the intercepted packet using the 'send packet' button", "Warning", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            var packet_display_object = packet_stream_view.SelectedItem;

            if ((string)object_helper.get_object_value(packet_display_object, "PayloadLength") == "0")
                return;

            int packet_number = int.Parse((string)object_helper.get_object_value(packet_display_object, "PacketNumber"));

            List<byte> packet_bytes = _packet_bytes[packet_number];

            System.Windows.Forms.Integration.WindowsFormsHost host = (WindowsFormsHost)grid1.Children[_child_id];

            Be.Windows.Forms.HexBox my_hex_box = (Be.Windows.Forms.HexBox)host.Child;

            my_hex_box.ByteProvider = new Be.Windows.Forms.DynamicByteProvider(packet_bytes);
            my_hex_box.StringViewVisible = true;
            my_hex_box.VScrollBarVisible = true;
            my_hex_box.ReadOnly = true;

            selected_packet_status.Content = "OLD PACKET (READONLY)";

            //grid1.Children[0].

            //packet_hex_editor.Stream = new System.IO.MemoryStream(packet_bytes.ToArray());
            //packet_hex_editor.ReadOnlyMode = true;
        }

        private void toggle_intercept_button_Click(object sender, RoutedEventArgs e)
        {
            if (_is_intercepting == true)
            {
                System.Windows.Forms.Integration.WindowsFormsHost host = (WindowsFormsHost)grid1.Children[_child_id];

                Be.Windows.Forms.HexBox my_hex_box = (Be.Windows.Forms.HexBox)host.Child;

                List<byte> send_bytes = new List<byte>();

                for (uint i = 0; i < my_hex_box.ByteProvider.Length; i++)
                    send_bytes.Add(my_hex_box.ByteProvider.ReadByte(i));

                my_hex_box.ByteProvider = new Be.Windows.Forms.DynamicByteProvider(new List<byte>());
                my_hex_box.ReadOnly = true;

                ui_send_intercepted_packet(send_bytes);

                selected_packet_status.Content = "NO PACKET (READONLY)";
            }

            _is_intercepting = !_is_intercepting;

            intercept_status.Content = "Intercepting: " + (_is_intercepting == true ? "yes" : "no");

            if (_is_intercepting == false)
            {
                cGlobalState.ui_toggle_intercept(_stream_id, "false", "127.0.0.1:1231");
                return;
            }

            _intercepting_client = ui_tcp_wait_for_connection();
        }
    }
}
