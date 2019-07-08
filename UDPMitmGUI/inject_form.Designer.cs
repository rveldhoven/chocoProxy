namespace UDPMitmGUI
{
    partial class inject_form
    {
        /// <summary>
        /// Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        /// <summary>
        /// Required method for Designer support - do not modify
        /// the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            this.ok_button = new System.Windows.Forms.Button();
            this.stop_button = new System.Windows.Forms.Button();
            this.comboBox1 = new System.Windows.Forms.ComboBox();
            this.label1 = new System.Windows.Forms.Label();
            this.mitm_udp = new System.Windows.Forms.RadioButton();
            this.mitm_tcp = new System.Windows.Forms.RadioButton();
            this.inject_evelated = new System.Windows.Forms.CheckBox();
            this.SuspendLayout();
            // 
            // ok_button
            // 
            this.ok_button.Location = new System.Drawing.Point(18, 51);
            this.ok_button.Margin = new System.Windows.Forms.Padding(3, 4, 3, 4);
            this.ok_button.Name = "ok_button";
            this.ok_button.Size = new System.Drawing.Size(146, 29);
            this.ok_button.TabIndex = 0;
            this.ok_button.Text = "Ok";
            this.ok_button.UseVisualStyleBackColor = true;
            this.ok_button.Click += new System.EventHandler(this.ok_button_Click);
            // 
            // stop_button
            // 
            this.stop_button.Location = new System.Drawing.Point(167, 51);
            this.stop_button.Margin = new System.Windows.Forms.Padding(3, 4, 3, 4);
            this.stop_button.Name = "stop_button";
            this.stop_button.Size = new System.Drawing.Size(135, 29);
            this.stop_button.TabIndex = 1;
            this.stop_button.Text = "Stop";
            this.stop_button.UseVisualStyleBackColor = true;
            this.stop_button.Click += new System.EventHandler(this.stop_button_Click);
            // 
            // comboBox1
            // 
            this.comboBox1.Location = new System.Drawing.Point(58, 16);
            this.comboBox1.Margin = new System.Windows.Forms.Padding(3, 4, 3, 4);
            this.comboBox1.Name = "comboBox1";
            this.comboBox1.Size = new System.Drawing.Size(244, 26);
            this.comboBox1.TabIndex = 2;
            // 
            // label1
            // 
            this.label1.AutoSize = true;
            this.label1.Location = new System.Drawing.Point(14, 20);
            this.label1.Name = "label1";
            this.label1.Size = new System.Drawing.Size(40, 20);
            this.label1.TabIndex = 3;
            this.label1.Text = "PID:";
            // 
            // mitm_udp
            // 
            this.mitm_udp.AutoSize = true;
            this.mitm_udp.Checked = true;
            this.mitm_udp.Location = new System.Drawing.Point(309, 19);
            this.mitm_udp.Margin = new System.Windows.Forms.Padding(3, 4, 3, 4);
            this.mitm_udp.Name = "mitm_udp";
            this.mitm_udp.Size = new System.Drawing.Size(113, 24);
            this.mitm_udp.TabIndex = 4;
            this.mitm_udp.Text = "MITM UDP";
            this.mitm_udp.UseVisualStyleBackColor = true;
            this.mitm_udp.CheckedChanged += new System.EventHandler(this.mitm_udp_CheckedChanged);
            // 
            // mitm_tcp
            // 
            this.mitm_tcp.AutoSize = true;
            this.mitm_tcp.Location = new System.Drawing.Point(309, 54);
            this.mitm_tcp.Margin = new System.Windows.Forms.Padding(3, 4, 3, 4);
            this.mitm_tcp.Name = "mitm_tcp";
            this.mitm_tcp.Size = new System.Drawing.Size(109, 24);
            this.mitm_tcp.TabIndex = 5;
            this.mitm_tcp.Text = "MITM TCP";
            this.mitm_tcp.UseVisualStyleBackColor = true;
            this.mitm_tcp.CheckedChanged += new System.EventHandler(this.mitm_tcp_CheckedChanged);
            // 
            // inject_evelated
            // 
            this.inject_evelated.AutoSize = true;
            this.inject_evelated.Checked = true;
            this.inject_evelated.CheckState = System.Windows.Forms.CheckState.Checked;
            this.inject_evelated.Location = new System.Drawing.Point(18, 86);
            this.inject_evelated.Margin = new System.Windows.Forms.Padding(3, 4, 3, 4);
            this.inject_evelated.Name = "inject_evelated";
            this.inject_evelated.Size = new System.Drawing.Size(329, 24);
            this.inject_evelated.TabIndex = 6;
            this.inject_evelated.Text = "Inject in elevated context (admin required)";
            this.inject_evelated.UseVisualStyleBackColor = true;
            // 
            // inject_form
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(9F, 20F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(423, 120);
            this.ControlBox = false;
            this.Controls.Add(this.inject_evelated);
            this.Controls.Add(this.mitm_tcp);
            this.Controls.Add(this.mitm_udp);
            this.Controls.Add(this.label1);
            this.Controls.Add(this.comboBox1);
            this.Controls.Add(this.stop_button);
            this.Controls.Add(this.ok_button);
            this.Margin = new System.Windows.Forms.Padding(3, 4, 3, 4);
            this.Name = "inject_form";
            this.SizeGripStyle = System.Windows.Forms.SizeGripStyle.Show;
            this.Text = "MITM new process";
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

        private System.Windows.Forms.Button ok_button;
        private System.Windows.Forms.Button stop_button;
        private System.Windows.Forms.ComboBox comboBox1;
        private System.Windows.Forms.Label label1;
        private System.Windows.Forms.RadioButton mitm_udp;
        private System.Windows.Forms.RadioButton mitm_tcp;
        private System.Windows.Forms.CheckBox inject_evelated;
    }
}