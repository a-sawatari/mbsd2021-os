
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
using System.Diagnostics;
using System.IO;
using System;
using System.Windows.Forms;
using System.Threading;

namespace os
{
    /// <summary>
    /// Do.xaml の相互作用ロジック
    /// </summary>
    public partial class Do : Window
    {
        public List<string> ToolD { get; internal set; }
        public List<string> ToolN { get; internal set; }
        public List<string> AddHttpList { get; internal set; }

        public Do()
        {
            InitializeComponent();
        }



        private void Window_ContentRendered(object sender, EventArgs e)
        {
            string check = "Csrf";
            Boolean csrfExec = false;
            List<string> Pathlist = new List<string>
            {
                @"C:\VulnDiag\pg\sql_injection.pyw",
                @"C:\VulnDiag\pg\cssp.pyw",
                @"C:\VulnDiag\pg\csrf.pyw",
                @"C:\VulnDiag\pg\os_command_injection.pyw",
                @"C:\VulnDiag\pg\directory_listing.pyw",
                @"C:\VulnDiag\pg\directory_traversal.pyw",
                @"C:\VulnDiag\pg\open_redirect.pyw",
                @"C:\VulnDiag\pg\http_header_injection.pyw"
            };

            for (int i = 0; i < Pathlist.Count(); i++)
            {
                for (int n = 0; n < ToolD.Count(); n++)
                {
                    string str = ToolD[n];

                    if (ToolD[n].Equals(check) && csrfExec == false)
                    {
                        for (int r = 0; r < AddHttpList.Count; r++)
                        {
                            string CsPythonApp = (@"C:\VulnDiag\pg\csrf.pyw");

                            var CsProcess = new Process
                            {
                                StartInfo = new ProcessStartInfo(@"C:\VulnDiag\python\pythonw.exe")
                                {
                                    UseShellExecute = false,
                                    RedirectStandardOutput = true,
                                    Arguments = CsPythonApp + " \"" + AddHttpList[r] + "\""
                                }
                            };

                            CsProcess.Start();
                            CsProcess.WaitForExit();
                            CsProcess.Close();

                            csrfExec = true;
                        }
                    }

                    

                    else if(ToolD[n].Equals(ToolN[i]) && str != check)
                    {
                        string myPythonApp = Pathlist[i];

                        var myProcess = new Process
                        {
                            
                            StartInfo = new ProcessStartInfo(@"C:\VulnDiag\python\pythonw.exe")
                            {
                                UseShellExecute = false,
                                RedirectStandardOutput = true,
                                Arguments = myPythonApp
                            }
                        };

                        myProcess.Start();
                        myProcess.WaitForExit();
                        myProcess.Close();
                    }
                }
            }
            Hide();
            System.Windows.MessageBox.Show("診断が終了しました。診断レポートは「"+@"C:\VulnDiag\report"+"」に出力されています。");
           
           
            string dlPythonApp = (@"C:\VulnDiag\pg\change_reportname.pyw");

            var dlProcess = new Process
            {
                
                StartInfo = new ProcessStartInfo(@"C:\VulnDiag\python\pythonw.exe")
                {
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    Arguments = dlPythonApp
                }
            };
            dlProcess.Start();
            dlProcess.WaitForExit();
            dlProcess.Close();

            DialogResult result = System.Windows.Forms.MessageBox.Show("TOPに戻りますか？", "", MessageBoxButtons.YesNo);
            if (result == System.Windows.Forms.DialogResult.Yes)
            {
                bool top_check = false;
                var top = new Window2
                {
                    Top_check = top_check
                };
                top.Show();
                Close();
            }
            else
            {
                Close();
            }
        }
    }
}

