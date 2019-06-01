using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace UDPMitmGUI
{
    public partial class inject_form : Form
    {
        public bool stop_clicked = true;
        public bool ok_clicked = false;
        public bool do_inject_elevated = false;
        public string pid = "";

        public bool do_mitm_udp = false;
        public bool do_mitm_tcp = false;

        public inject_form()
        {
            InitializeComponent();
            do_mitm_udp = mitm_udp.Checked;
            do_mitm_tcp = mitm_tcp.Checked;
        }

        private void ok_button_Click(object sender, EventArgs e)
        {
            ok_clicked = true;
            stop_clicked = false;
            pid = textBox1.Text;
            do_mitm_udp = mitm_udp.Checked;
            do_mitm_tcp = mitm_tcp.Checked;
            do_inject_elevated = inject_evelated.Checked;
            this.Close();
        }

        private void stop_button_Click(object sender, EventArgs e)
        {
            ok_clicked = false;
            stop_clicked = true;
            do_mitm_udp = mitm_udp.Checked;
            do_mitm_tcp = mitm_tcp.Checked;
            this.Close();
        }

        private void mitm_tcp_CheckedChanged(object sender, EventArgs e)
        {
            mitm_udp.Checked = !mitm_tcp.Checked;
        }

        private void mitm_udp_CheckedChanged(object sender, EventArgs e)
        {
            mitm_tcp.Checked = !mitm_udp.Checked;
        }
    }
}
