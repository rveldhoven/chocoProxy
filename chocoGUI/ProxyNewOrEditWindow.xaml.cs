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

namespace chocoGUI
{
    /// <summary>
    /// Interaction logic for ProxyNewOrEditWindow.xaml
    /// </summary>
    /// 

    public partial class ProxyNewOrEditWindow : Window
    {
        public bool was_ok = false;
        public string ip = "";
        public string port = "";
        public string u_ip = "";
        public string u_port = "";
        public string m_ip = "";
        public string m_port = "";
        public string m_data = "";

        public ProxyNewOrEditWindow()
        {
            InitializeComponent();
        }

        private void Button_Click(object sender, RoutedEventArgs e)
        {
            ip = proxy_ip_textbox.Text;
            port = proxy_port_textbox.Text;
            u_ip = udp_proxy_ip_textbox.Text;
            u_port = udp_proxy_port_textbox.Text;
            m_ip = management_ip_textbox.Text;
            m_port = management_port_textbox.Text;
            m_data = metadata_textbox.Text;
            was_ok = true;
            this.Close();
        }

        private void Button_Click_1(object sender, RoutedEventArgs e)
        {
            this.Close();
        }
    }
}
