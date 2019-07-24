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

        public DispatcherTimer ui_dispatcher_timer = new DispatcherTimer();

        private void ui_populate_packet_view()
        {
            // There's a race condition here, but imo not worth changing the architecture to fix yet.
            if (cFileUtilities.get_size(_backend_file) == _backend_size)
                return;

            _backend_size = cFileUtilities.get_size(_backend_file);

            ICaptureDevice pcap_device = null;

            var gridView = new GridView();

            gridView.Columns.Add(new GridViewColumn() { Header = "Packet no.", DisplayMemberBinding = new Binding("PacketNumber") });
            gridView.Columns.Add(new GridViewColumn() { Header = "Source", DisplayMemberBinding = new Binding("Source") });
            gridView.Columns.Add(new GridViewColumn() { Header = "Destination", DisplayMemberBinding = new Binding("Destination") });
            gridView.Columns.Add(new GridViewColumn() { Header = "Payload Length", DisplayMemberBinding = new Binding("PayloadLength") });
            
            try
            {
                pcap_device = new SharpPcap.LibPcap.CaptureFileReaderDevice(_backend_file);
                pcap_device.Open();

                RawCapture capture;
                int current_packet = 0;

                while((capture = pcap_device.GetNextPacket()) != null)
                {
                    var eth_packet = PacketDotNet.Packet.ParsePacket(capture.LinkLayerType, capture.Data);

                    PacketDotNet.IPPacket ip_packet = eth_packet.Extract<PacketDotNet.IPPacket>();
                    PacketDotNet.TcpPacket tcp_packet = eth_packet.Extract<PacketDotNet.TcpPacket>();

                    packet_stream_view.View = gridView;

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
                MessageBox.Show("Error: " + e.Message, "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }

            if(pcap_device != null)
                pcap_device.Close();
        }

        private void ui_update_tick(object sender, EventArgs e)
        {
            ui_populate_packet_view();
        }

        public StreamWindow(string backend_file)
        {
            InitializeComponent();

            _backend_file = backend_file;

            ui_dispatcher_timer.Tick += new EventHandler(ui_update_tick);
            ui_dispatcher_timer.Interval = new TimeSpan(0, 0, 1);
            ui_dispatcher_timer.Start();
        }
    }
}
