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
using System.Windows.Navigation;
using System.Windows.Shapes;
using System.Windows.Threading;

namespace chocoGUI
{
    static class object_helper
    {
        public static object get_object_value(this object obj, string name)
        {
            return obj.GetType().GetProperty(name).GetValue(obj, null);
        }
    }

    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    /// 
    public partial class MainWindow : Window
    {
        public DispatcherTimer ui_dispatcher_timer = new DispatcherTimer();

        public MainWindow()
        {
            InitializeComponent();

            var tcp_gridview = new GridView();

            tcp_gridview.Columns.Add(new GridViewColumn() { Header = "Source proxy", DisplayMemberBinding = new Binding("SourceProxy") });
            tcp_gridview.Columns.Add(new GridViewColumn() { Header = "Source IP", DisplayMemberBinding = new Binding("SourceIP") });
            tcp_gridview.Columns.Add(new GridViewColumn() { Header = "Destination IP", DisplayMemberBinding = new Binding("DestinationIP") });
            tcp_gridview.Columns.Add(new GridViewColumn() { Header = "Source port", DisplayMemberBinding = new Binding("SourcePort") });
            tcp_gridview.Columns.Add(new GridViewColumn() { Header = "Destination port", DisplayMemberBinding = new Binding("DestinationPort") });
            tcp_gridview.Columns.Add(new GridViewColumn() { Header = "Stream start", DisplayMemberBinding = new Binding("StreamStart") });
            tcp_gridview.Columns.Add(new GridViewColumn() { Header = "Proxy connected", DisplayMemberBinding = new Binding("ProxyConnected") });

            tcp_stream_view.View = tcp_gridview;


            var udp_gridview = new GridView();

            udp_gridview.Columns.Add(new GridViewColumn() { Header = "Source proxy", DisplayMemberBinding = new Binding("SourceProxy") });
            udp_gridview.Columns.Add(new GridViewColumn() { Header = "Source IP", DisplayMemberBinding = new Binding("SourceIP") });
            udp_gridview.Columns.Add(new GridViewColumn() { Header = "Destination IP", DisplayMemberBinding = new Binding("DestinationIP") });
            udp_gridview.Columns.Add(new GridViewColumn() { Header = "Source port", DisplayMemberBinding = new Binding("SourcePort") });
            udp_gridview.Columns.Add(new GridViewColumn() { Header = "Destination port", DisplayMemberBinding = new Binding("DestinationPort") });
            udp_gridview.Columns.Add(new GridViewColumn() { Header = "Stream start", DisplayMemberBinding = new Binding("StreamStart") });
            udp_gridview.Columns.Add(new GridViewColumn() { Header = "Proxy connected", DisplayMemberBinding = new Binding("ProxyConnected") });

            udp_stream_view.View = udp_gridview;

            var proxy_gridview = new GridView();

            proxy_gridview.Columns.Add(new GridViewColumn() { Header = "Proxy metadata", DisplayMemberBinding = new Binding("ProxyMetadata") });
            proxy_gridview.Columns.Add(new GridViewColumn() { Header = "Proxy SOCKS address", DisplayMemberBinding = new Binding("ProxySOCKSAddress") });
            proxy_gridview.Columns.Add(new GridViewColumn() { Header = "Proxy UDP address", DisplayMemberBinding = new Binding("ProxyUDPAddress") });
            proxy_gridview.Columns.Add(new GridViewColumn() { Header = "Management address", DisplayMemberBinding = new Binding("MangementAddress") });
            proxy_gridview.Columns.Add(new GridViewColumn() { Header = "Pcap directory", DisplayMemberBinding = new Binding("PcapDirectory") });

            proxy_view.View = proxy_gridview;

            cGlobalState.background_thread_start();

            ui_dispatcher_timer.Tick += new EventHandler(ui_update_tick);
            ui_dispatcher_timer.Interval = new TimeSpan(0, 0, 1);
            ui_dispatcher_timer.Start();
        }

        private void ui_update_tick(object sender, EventArgs e)
        {
            var tcp_streams = cGlobalState.ui_tcp_streams_get();

            foreach (var tcp_stream in tcp_streams)
            {
                object stream_item = new
                {
                    SourceProxy = tcp_stream.source_process_name,
                    SourceIP = tcp_stream.source_ip,
                    DestinationIP = tcp_stream.destination_ip,
                    SourcePort = tcp_stream.source_port,
                    DestinationPort = tcp_stream.destination_port,
                    StreamStart = tcp_stream.stream_start,
                    ProxyConnected = (tcp_stream.proxy_connected == true ? "yes" : "no"),
                    FileName = tcp_stream.backend_file,
                };

                if (tcp_stream_view.Items.Contains(stream_item) == false)
                    tcp_stream_view.Items.Add(stream_item);
            }


            var udp_streams = cGlobalState.ui_udp_streams_get();

            foreach (var udp_stream in udp_streams)
            {
                object stream_item = new
                {
                    SourceProxy = udp_stream.source_process_name,
                    SourceIP = udp_stream.source_ip,
                    DestinationIP = udp_stream.destination_ip,
                    SourcePort = udp_stream.source_port,
                    DestinationPort = udp_stream.destination_port,
                    StreamStart = udp_stream.stream_start,
                    ProxyConnected = (udp_stream.proxy_connected == true ? "yes" : "no"),
                    FileName = udp_stream.backend_file,
                };

                if (udp_stream_view.Items.Contains(stream_item) == false)
                    udp_stream_view.Items.Add(stream_item);
            }

            var running_proxies = cGlobalState.ui_proxy_process_get();

            List<object> current_proxy_objects = new List<object>();

            foreach (var proxy_process in running_proxies)
            {
                object stream_item = new
                {
                    ProxyMetadata = proxy_process.proxy_process_metadata,
                    ProxySOCKSAddress = proxy_process.proxy_socks_ip + ":" + proxy_process.proxy_socks_port,
                    ProxyUDPAddress = proxy_process.proxy_udp_ip + ":" + proxy_process.proxy_udp_port,
                    MangementAddress = proxy_process.management_ip + ":" + proxy_process.management_port,
                    PcapDirectory = proxy_process.pcap_dir,
                };

                current_proxy_objects.Add(stream_item);

                if (proxy_view.Items.Contains(stream_item) == false)
                    proxy_view.Items.Add(stream_item);
            }

            bool changes = true;

            while(changes == true)
            {
                changes = false;

                int remove_index = 0;

                for (remove_index = 0; remove_index < proxy_view.Items.Count; remove_index++)
                {
                    if (current_proxy_objects.Contains(proxy_view.Items[remove_index]) == false)
                    {
                        changes = true;
                        break;
                    }
                }

                if (changes == false)
                    break;

                proxy_view.Items.RemoveAt(remove_index);
            }
        }   

        private void MenuItem_Click(object sender, RoutedEventArgs e)
        {

        }

        private void OpenTCPStreamButton_Click(object send, RoutedEventArgs e)
        {
            if (tcp_stream_view.SelectedIndex == -1)
                return;

            var display_object = tcp_stream_view.SelectedItem;

            string pcap_file = (string)object_helper.get_object_value(display_object, "FileName");
            string stream_id = (string)object_helper.get_object_value(display_object, "StreamStart");

            var stream_window = new StreamWindow(pcap_file, stream_id, "tcp");
            stream_window.Show();
        }
        private void OpenUDPStreamButton_Click(object send, RoutedEventArgs e)
        {
            if (udp_stream_view.SelectedIndex == -1)
                return;

            var display_object = udp_stream_view.SelectedItem;

            string pcap_file = (string)object_helper.get_object_value(display_object, "FileName");
            string stream_id = (string)object_helper.get_object_value(display_object, "StreamStart");

            var stream_window = new StreamWindow(pcap_file, stream_id, "udp");
            stream_window.Show();
        }


        private void Inject_button_Click(object sender, RoutedEventArgs e)
        {
            var inject_window = new InjectWindow();
            inject_window.ShowDialog();
        }

        private void Toggle_global_intercept_Click(object sender, RoutedEventArgs e)
        {
            cGlobalState.global_intercept_flag = !cGlobalState.global_intercept_flag;

            intercept_state_label.Content = "Global intercept state: " + (cGlobalState.global_intercept_flag == true ? "true" : "false");

            cGlobalState.ui_toggle_global_intercept();
        }

        private void Create_proxy_button_Click(object sender, RoutedEventArgs e)
        {
            var proxy_edit_window = new ProxyNewOrEditWindow();

            bool? result = proxy_edit_window.ShowDialog();

            if (result.HasValue == false)
                return;

            if (proxy_edit_window.was_ok == false)
                return;

            try
            {
                if (cGlobalState.ui_proxy_process_start(proxy_edit_window.m_data, proxy_edit_window.ip, proxy_edit_window.port, proxy_edit_window.u_ip, proxy_edit_window.u_port, proxy_edit_window.m_ip, proxy_edit_window.m_port) == false)
                    MessageBox.Show("Failed to start proxy process", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            catch (Exception error)
            {
                MessageBox.Show(error.Message, "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void Manage_scripts_mouse_up(object send, RoutedEventArgs e)
        {
            if (proxy_view.SelectedIndex == -1)
            {
                MessageBox.Show("Select a proxy from the list to the left first", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                return;
            }

            var display_object = proxy_view.SelectedItem;

            // The proxy's name is also it's adress since it's unique
            string proxy_address = (string)object_helper.get_object_value(display_object, "ProxyAddress");

            var script_manager_window = new ScriptManagerWindow(proxy_address, "Global");
            script_manager_window.Show();
        }
    }
}
