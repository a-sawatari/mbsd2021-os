using System.Collections.Generic;
using System.Windows;
using System.Diagnostics;
using System.IO;
using System;
using System.Windows.Documents;
using System.Windows.Controls;
using System.Collections.ObjectModel;
using System.Windows.Forms;
using System.Threading;
using System.Threading.Tasks;


namespace os
{
    /// <summary>
    /// HttpWin.xaml の相互作用ロジック
    /// </summary>
    public partial class HttpWin : Window
    {
       
        public DialogResult Result { get; internal set; }
        public List<string> ToolD { get; internal set; }
        public List<string> ToolN { get; internal set; }
        public List<string> HostList { get; internal set; }

        public HttpWin()
        {
            InitializeComponent();
        }
        private void Window_ContentRendered(object sender, EventArgs e)
        {
            HttpAdd();
        }
        
        public void HttpAdd()
        {       
                string Host = HostList[0];
                String Insertpy = (@"C:\VulnDiag\pg\db_insert.pyw");

                var insertProcess = new Process
                {

                    StartInfo = new ProcessStartInfo(@"C:\VulnDiag\python\pythonw.exe")
                    {
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        Arguments = Insertpy + " " + Host
                    }
                };

                insertProcess.Start();
                insertProcess.WaitForExit();
                insertProcess.Close();

            var Output = new Output();

            foreach (string n in Output.Print())
            {
                HttpList.Items.Add(n);
            }
        }
        private void Button_Click(object sender, RoutedEventArgs e)
        {
            
            List<string> AddHttpList = new List<string>();

            int cnt = HttpList.SelectedItems.Count;

            for(int i = 0; cnt > i; i++)
            {
                AddHttpList.Add(HttpList.SelectedItems[i].ToString());
            }

            DialogResult result = System.Windows.Forms.MessageBox.Show("診断の実行に移ります。");
            if (result == System.Windows.Forms.DialogResult.OK)
            {
                var w5 = new Do();
                w5.ToolD = ToolD;
                w5.ToolN = ToolN;
                w5.Add = AddHttpList;
                w5.Show();
                Close();
            }

        }
        class Output
        {
            public IEnumerable<string> Print()
            {

                String Printpy = (@"C:\VulnDiag\pg\db_print.pyw");

                var printProcess = new Process
                {
                    
                    StartInfo = new ProcessStartInfo(@"C:\VulnDiag\python\pythonw.exe")
                    {
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        Arguments = Printpy
                    }
                };

                printProcess.Start();
                StreamReader printReader = printProcess.StandardOutput;
                string string_http = printReader.ReadLine();

                while (string_http != null)
                {
                    yield return string_http;
                    string_http = printReader.ReadLine();
                }
                printProcess.WaitForExit();
                printProcess.Close();
            }
        }
    }
}