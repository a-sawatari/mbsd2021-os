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
    /// host.xaml の相互作用ロジック
    /// </summary>
    public partial class host : Window
    {
        

        public host()
        {
            InitializeComponent();
            
        }

        private void Button_Click(object sender, RoutedEventArgs e)
        {
            List<string> HostList = new List<string>();
            HostList.Add(Host.Text);
            var vul = new Vul();
            vul.HostList = HostList;
            vul.Show();
            Close();
        }

    private void Button_Click_1(object sender, RoutedEventArgs e)
        {
            var top = new Window2();
            top.Show();
            Close();
        }
    }
}
