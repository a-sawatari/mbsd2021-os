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
        //public string Hostt;
        public Vul()
        {
            InitializeComponent();

        }

        public List<string> HostList { get; internal set; }

        public void Button_Click(object sender, RoutedEventArgs e)
        {
            List<string> ToolList = new List<string>();

            List<string> ToolName = new List<string>();
            ToolName.Add("Sqlin");
            ToolName.Add("Xss");
            ToolName.Add("Csrf");
            ToolName.Add("Oscmd");
            ToolName.Add("Dirl");
            ToolName.Add("Dirt");
            ToolName.Add("Red");
            ToolName.Add("Http");

            List<bool?> Checklist = new List<bool?>();
            Checklist.Add(Sqlin.IsChecked);
            Checklist.Add(Xss.IsChecked);
            Checklist.Add(Csrf.IsChecked);
            Checklist.Add(Oscmd.IsChecked);
            Checklist.Add(Dirl.IsChecked);
            Checklist.Add(Dirt.IsChecked);
            Checklist.Add(Red.IsChecked);
            Checklist.Add(Http.IsChecked);

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
                var w4 = new HttpWin();
                w4.ToolD = ToolList;
                w4.ToolN = ToolName;
                w4.HostList = HostList;
                w4.Show();
            }
            else
            {
                var w7 = new Do();
                w7.ToolD = ToolList;
                w7.ToolN = ToolName;
                w7.Show();
            }
            
            Close();
        }

        public void Button_Click1(object sender, RoutedEventArgs e)
        {
            var back = new host();
            back.Show();
            Close();
        }
    }
}




        