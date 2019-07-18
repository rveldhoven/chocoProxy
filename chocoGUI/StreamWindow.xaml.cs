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
    /// Interaction logic for StreamWindow.xaml
    /// </summary>
    public partial class StreamWindow : Window
    {
        private cTCPStream _our_stream = null;

        public StreamWindow(cTCPStream stream)
        {
            InitializeComponent();

            _our_stream = stream;

        }
    }
}
