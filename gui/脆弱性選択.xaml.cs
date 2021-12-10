using System.Collections.Generic;
using System.Windows;
using System.Diagnostics;
using System.IO;
using System;
using System.Windows.Documents;
using System.Windows.Forms;
using MessageBox = System.Windows.Forms.MessageBox;

namespace os
{
    /// <summary>
    /// 脆弱性設定.xaml の相互作用ロジック
    /// </summary>
    public partial class Vul : Window
    {
        public Vul()
        {
            InitializeComponent();
        }

        public List<string> HostList { get; internal set; }
        private void Window_ContentRendered(object sender, EventArgs e)
        {
            Insert();
        }
        public void Button_Click(object sender, RoutedEventArgs e)
        {
            List<string> ToolList = new List<string>();

            List<string> ToolName = new List<string>
            {
                "Sqlin",
                "Xss",
                "Csrf",
                "Oscmd",
                "Dirl",
                "Dirt",
                "Red",
                "Http"
            };

            List<bool?> Checklist = new List<bool?>
            {
                Sqlin.IsChecked,
                Xss.IsChecked,
                Csrf.IsChecked,
                Oscmd.IsChecked,
                Dirl.IsChecked,
                Dirt.IsChecked,
                Red.IsChecked,
                Http.IsChecked
            };

            for (int r = 0; r < Checklist.Count; r++)
            {
                if (Checklist[r] == true && r != 2)
                {
                    ToolList.Add(ToolName[r]);
                }
                if (r == 2 && Checklist[r] == true)
                {
                    MessageBox.Show("CSRFが選択されました。ログイン状態において、特定副作用を実行した通信を選択してください。");

                    ToolList.Add(ToolName[r]);
                }
            }

            if(Checklist[2] == true)
            {
                var w4 = new HttpWin
                {
                    ToolD = ToolList,
                    ToolN = ToolName
                };
                w4.Show();
            }
            else
            {
                var w7 = new Do
                {
                    ToolD = ToolList,
                    ToolN = ToolName
                };
                w7.Show();
            }
            
            Close();
        }

        public void Insert()
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
        }

        public void Button_Click1(object sender, RoutedEventArgs e)
        {
            var back = new host();
            back.Show();
            Close();
        }

       
    }
}




        