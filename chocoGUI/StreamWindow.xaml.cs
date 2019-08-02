using SharpPcap;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
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
        private string _backend_file = null;
        private long _backend_size = 0;
        private string _stream_id = "";
        private int _child_id = 0;

        private List<List<byte>> _packet_bytes = new List<List<byte>>();

        public DispatcherTimer ui_dispatcher_timer = new DispatcherTimer();

        int tab_counter = 0;

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

        private void ui_update_tick(object sender, EventArgs e)
        {
            ui_populate_packet_view();
        }

        public StreamWindow(string backend_file, string stream_id)
        {
            InitializeComponent();

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

            ui_dispatcher_timer.Tick += new EventHandler(ui_update_tick);
            ui_dispatcher_timer.Interval = new TimeSpan(0, 0, 0, 0, 500);
            ui_dispatcher_timer.Start();
        }

        private void SendToRepeater_Click(object sender, RoutedEventArgs e)
        {
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

            //grid1.Children[0].

            //packet_hex_editor.Stream = new System.IO.MemoryStream(packet_bytes.ToArray());
            //packet_hex_editor.ReadOnlyMode = true;
        }
    }
}
