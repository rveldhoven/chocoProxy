﻿using System;
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
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        public DispatcherTimer ui_dispatcher_timer = new DispatcherTimer() ;


        public MainWindow()
        {
            InitializeComponent();

            cGlobalState.background_thread_start();

            ui_dispatcher_timer.Tick += new EventHandler(ui_update_tick);
            ui_dispatcher_timer.Interval = new TimeSpan(0, 0, 1);
            ui_dispatcher_timer.Start();
        }

        private void ui_update_tick(object sender, EventArgs e)
        {
            var tcp_streams = cGlobalState.ui_tcp_streams_get();

            var gridView = new GridView();

            gridView.Columns.Add(new GridViewColumn() { Header = "Source process", DisplayMemberBinding = new Binding("SourceProcess") });
            gridView.Columns.Add(new GridViewColumn() { Header = "Source IP", DisplayMemberBinding = new Binding("SourceIP") });
            gridView.Columns.Add(new GridViewColumn() { Header = "Destination IP", DisplayMemberBinding = new Binding("DestinationIP") });
            gridView.Columns.Add(new GridViewColumn() { Header = "Source port", DisplayMemberBinding = new Binding("SourcePort") });
            gridView.Columns.Add(new GridViewColumn() { Header = "Destination port", DisplayMemberBinding = new Binding("DestinationPort") });
            gridView.Columns.Add(new GridViewColumn() { Header = "Stream start", DisplayMemberBinding = new Binding("StreamStart") });
            gridView.Columns.Add(new GridViewColumn() { Header = "Proxy connected", DisplayMemberBinding = new Binding("ProxyConnected") });

            tcp_stream_view.View = gridView;

            foreach (var tcp_stream in tcp_streams)
            {
                object stream_item = new
                {
                    SourceProcess = tcp_stream.source_process_name,
                    SourceIP = tcp_stream.source_ip,
                    DestinationIP = tcp_stream.destination_ip,
                    SourcePort = tcp_stream.source_port,
                    DestinationPort = tcp_stream.destination_port,
                    StreamStart = tcp_stream.stream_start,
                    ProxyConnected = (tcp_stream.proxy_connected == true ? "yes" : "no")
                };

                if (tcp_stream_view.Items.Contains(stream_item) == false)
                    tcp_stream_view.Items.Add(stream_item); 
            }
        }
    }
}