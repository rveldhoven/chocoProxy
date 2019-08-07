using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Diagnostics;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Shapes;
using System.Windows.Threading;

namespace chocoGUI
{
    /// <summary>
    /// Interaction logic for InjectWindow.xaml
    /// </summary>
    public partial class InjectWindow : Window
    {
        
        public InjectWindow()
        {
            InitializeComponent();
            TcpRadioButton.IsChecked = true;
            var process_gridview = new GridView();

            process_gridview.Columns.Add(new GridViewColumn() { Header = "Process name", DisplayMemberBinding = new Binding("ProcessName") });
            process_gridview.Columns.Add(new GridViewColumn() { Header = "Arch", DisplayMemberBinding = new Binding("ProcessArch") });
            process_gridview.Columns.Add(new GridViewColumn() { Header = "Process ID", DisplayMemberBinding = new Binding("ProcessID") });

            process_view.View = process_gridview;

            var proxy_gridview = new GridView();

            proxy_gridview.Columns.Add(new GridViewColumn() { Header = "Proxy metadata", DisplayMemberBinding = new Binding("ProxyMetadata") });
            proxy_gridview.Columns.Add(new GridViewColumn() { Header = "Proxy SOCKS address", DisplayMemberBinding = new Binding("ProxySOCKSAddress") });
            proxy_gridview.Columns.Add(new GridViewColumn() { Header = "Proxy UDP address", DisplayMemberBinding = new Binding("ProxyUDPAddress") });
            proxy_gridview.Columns.Add(new GridViewColumn() { Header = "Management address", DisplayMemberBinding = new Binding("MangementAddress") });
            proxy_gridview.Columns.Add(new GridViewColumn() { Header = "Pcap directory", DisplayMemberBinding = new Binding("PcapDirectory") });

            proxy_view.View = proxy_gridview;

            ui_update_tick();
        }
        private void ui_update_tick()
        {
            List<object> current_process_list = new List<object>();
            Process[] process_list = Process.GetProcesses();

            foreach (Process the_process in process_list)
            {
                object process_item = new
                {
                    ProcessName = the_process.ProcessName,
                    ProcessArch = cGlobalState.IsWin64Emulator(the_process) ? "x64" : "x86" ,
                    ProcessID = the_process.Id
                };

                current_process_list.Add(process_item);

                if (process_view.Items.Contains(process_item) == false)
                    process_view.Items.Add(process_item);
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
        }
        private void inject_process_button(object sender, RoutedEventArgs e)
        {
            if (process_view.SelectedIndex == -1)
            {
                MessageBox.Show("Select a process from the list.", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                return;
            }

            if (proxy_view.SelectedIndex == -1)
            {
                MessageBox.Show("Select a proxy from the list.", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                return;
            }

            var selected_process = process_view.SelectedItem;

            int process_ID = (int)object_helper.get_object_value(selected_process, "ProcessID");
            string process_arch = (string)object_helper.get_object_value(selected_process, "ProcessArch");

            var selected_proxy = proxy_view.SelectedItem;

            string ip = "";
            string port = "";

            if (TcpRadioButton.IsChecked.Value == true)
            {
                ip = ((string)object_helper.get_object_value(selected_proxy, "ProxySOCKSAddress")).Split(':')[0];
                port = ((string)object_helper.get_object_value(selected_proxy, "ProxySOCKSAddress")).Split(':')[1];
            }
            else
            {
                ip = ((string)object_helper.get_object_value(selected_proxy, "ProxyUDPAddress")).Split(':')[0];
                port = ((string)object_helper.get_object_value(selected_proxy, "ProxyUDPAddress")).Split(':')[1];
            }
            //// <dll> <pid> <ip> <port> <fun>
            Process new_injector = new Process();
            new_injector.StartInfo.UseShellExecute = true;
            new_injector.StartInfo.Verb = "runas";

            new_injector.StartInfo.Arguments = '"' + System.IO.Path.Combine(Environment.CurrentDirectory, (TcpRadioButton.IsChecked.Value ? "chocoSOCKSDLL" : "chocoUDPDLL") + (process_arch == "x86" ? "Win32" : "x64")) + ".dll\" " + process_ID.ToString() + " " + ip + " " + port + " sendto";
            new_injector.StartInfo.FileName = "chocoInjector" + (process_arch == "x86" ? "Win32" : "x64") + ".exe";

            new_injector.Start();
        }

        private void Check_TCP(object sender, RoutedEventArgs e)
        {
            UdpRadioButton.IsChecked = false;
        }

        private void Check_UDP(object sender, RoutedEventArgs e)
        {
            TcpRadioButton.IsChecked = false;
        }

        private void Cancel_Inject(object sender, RoutedEventArgs e)
        {
            this.Close();
        }
    }
}
