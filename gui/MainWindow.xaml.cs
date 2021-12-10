using System;
using System.Collections.Generic;
using System.Diagnostics;
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
using System.Windows.Navigation;
using System.Windows.Shapes;

namespace os
{
    /// <summary>
    /// MainWindow.xaml の相互作用ロジック
    /// </summary>
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
  
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

            var w2 = new Window2();
            w2.Show();
            Close();
        }
        
    }
}
