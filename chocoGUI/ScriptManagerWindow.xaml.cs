using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.IO;
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
    /// Interaction logic for ScriptManagerWindow.xaml
    /// </summary>
    public partial class ScriptManagerWindow : Window
    {
        private string _proxy_id = "";
        private string _stream_id = "";

        private bool _is_running = true;

        public DispatcherTimer ui_dispatcher_timer = new DispatcherTimer();

        private void ui_populate_script_view()
        {
            Dictionary<string, Dictionary<string, cPythonScript>> scripts = cGlobalState.ui_scripts_scripts_get(_proxy_id);

            Dictionary<string, cPythonScript> intresting_scripts = scripts[_stream_id];

            foreach (var string_object in intresting_scripts)
            {
                object script_view_item = new
                {
                    ScriptName = string_object.Key,
                    ScriptDirection = string_object.Value.direction,
                    ContentsAbriv = string_object.Value.script.SkipWhile((c) => c != '\n').Take(10),
                };

                if (scripts_view.Items.Contains(string_object) == false)
                    scripts_view.Items.Add(string_object);
            }

        }

        private void ui_update_tick(object sender, EventArgs e)
        {
            ui_populate_script_view();
        }

        public ScriptManagerWindow(string proxy_id, string stream_id)
        {
            InitializeComponent();

            _proxy_id = proxy_id;
            _stream_id = stream_id;

            this.Title += proxy_id;

            var gridView = new GridView();

            gridView.Columns.Add(new GridViewColumn() { Header = "Script name", DisplayMemberBinding = new Binding("ScriptName") });
            gridView.Columns.Add(new GridViewColumn() { Header = "Script direction", DisplayMemberBinding = new Binding("ScriptDirection") });
            gridView.Columns.Add(new GridViewColumn() { Header = "Script contents...", DisplayMemberBinding = new Binding("ContentsAbriv") });

            scripts_view.View = gridView;

            ui_dispatcher_timer.Tick += new EventHandler(ui_update_tick);
            ui_dispatcher_timer.Interval = new TimeSpan(0, 0, 0, 1, 0);
            ui_dispatcher_timer.Start();
        }

        private void remove_script_Click(object sender, RoutedEventArgs e)
        {
            if (scripts_view.SelectedIndex == -1)
                return;

            var display_object = scripts_view.SelectedItem;

            // The proxy's name is also it's adress since it's unique
            string script_name = (string)object_helper.get_object_value(display_object, "ScriptName");

            cGlobalState.ui_script_delete_script(_proxy_id, _stream_id, script_name);
        }

        private void add_script_button_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog dialog = new OpenFileDialog();

            dialog.Filter = "Python files (*.py)|*.py|All files(*.*)|*.*";

            if (dialog.ShowDialog() == false)
                return;

            if (dialog.FileNames.Length == 0)
                return;

            // TODO: refactor this code, why put it in an object just to then send it as seperate arguments?
            Dictionary<string, cPythonScript> scripts = new Dictionary<string, cPythonScript>();

            foreach (string filename in dialog.FileNames)
            {
                string script_contents = File.ReadAllText(filename);

                if (script_contents.Length == 0)
                    continue;

                string script_name = System.IO.Path.GetFileNameWithoutExtension(filename);
                string script_direction = "Both";

                scripts[script_name] = new cPythonScript
                {
                    direction = script_direction,
                    script = script_contents,
                };
            }

            foreach (var K_v in scripts)
            {
                cGlobalState.ui_script_add_script(_proxy_id, _stream_id, K_v.Key, K_v.Value.direction, K_v.Value.script);
            }
        }
    }
}
