using System;
using System.Collections.Generic;
using System.Diagnostics;
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

namespace os
{
    /// <summary>
    /// Window2.xaml の相互作用ロジック
    /// </summary>
    public partial class Window2 : Window
    { 
        public Window2()
        {
            InitializeComponent();
        }
        public bool Top_check { get; internal set; }

        private void Window_ContentRendered(object sender, EventArgs e)
        {
            if (Top_check == false)
            {
                String Deletepy = (@"C:\VulnDiag\pg\delete.pyw");

                var DeleteProcess = new Process
                {

                    StartInfo = new ProcessStartInfo(@"C:\VulnDiag\python\pythonw.exe")
                    {
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        Arguments = Deletepy
                    }
                };

                DeleteProcess.Start();
                DeleteProcess.WaitForExit();
                DeleteProcess.Close();

                String Createpy = (@"C:\VulnDiag\pg\db_create.pyw");

                var createProcess = new Process
                {

                    StartInfo = new ProcessStartInfo(@"C:\VulnDiag\python\pythonw.exe")
                    {
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        Arguments = Createpy
                    }
                };

                createProcess.Start();
                createProcess.WaitForExit();
                createProcess.Close();
                Top_check = true;
            }
        }

        private void Button_Click(object sender, RoutedEventArgs e)
        {
            var w3 = new Window3();
            w3.Show();
            Close();
        }

        private void Button_Click_1(object sender, RoutedEventArgs e)
        {
            var h = new host();
            h.Show();
            Close();
        }

        
    }

}
