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
using System.Diagnostics;
using System.IO;


namespace os
{
    /// <summary>
    /// Window3.xaml の相互作用ロジック
    /// </summary>
    public partial class Window3 : Window
    {
        public Window3()
        {
            InitializeComponent();
        }

       
        private void Button_Click_1(object sender, RoutedEventArgs e)
        {
            var top = new Window2();
            top.Show();
            Close();
        }

        private void Button_Click_2(object sender, RoutedEventArgs e)
        {
            string Url = url.Text;

            string myPythonApp = (@"C:\VulnDiag\pg\crawling.pyw");

            var myProcess = new Process
            {
                
                StartInfo = new ProcessStartInfo(@"C:\VulnDiag\python\pythonw.exe")
                {
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    Arguments = myPythonApp + " " + Url
                }
            };

            myProcess.Start();
            StreamReader myStreamReader = myProcess.StandardOutput;
            myProcess.WaitForExit();
            myProcess.Close();

            MessageBox.Show("クローリングが終わりました。TOPに戻ります。");
            var top = new Window2();
            top.Show();
            Close();
        }
    }
}
