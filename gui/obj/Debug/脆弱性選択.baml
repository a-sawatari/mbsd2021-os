   M S B A M L   `   `   `  ����=  9os, Version=1.0.0.0, Culture=neutral, PublicKeyToken=nullclr-namespace:osos  5   	       os.Vul   5   	   W SPresentationCore, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35R NWindowsBase, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35\ XPresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35D 9http://schemas.microsoft.com/winfx/2006/xaml/presentation    5   	   R NSystem.Xaml, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089:x,http://schemas.microsoft.com/winfx/2006/xaml     5   	   @d2http://schemas.microsoft.com/expression/blend/2008     5   	   Jmc;http://schemas.openxmlformats.org/markup-compatibility/2006     5   	   "localclr-namespace:os     5   	   _ [MaterialDesignThemes.Wpf, Version=4.2.1.2, Culture=neutral, PublicKeyToken=df2a72020bd7962aFmaterialDesign1http://materialdesigninxaml.net/winfx/xaml/themes  6(   -   5          � Title$   ��5	   	   $	��450��6   $	��800��6   .��5      � .+�5   
   (  "MaterialDesignThemes.Wpf.ColorZone     Mode$ 
PrimaryMid=�5      $��16q�5      .��5      ��  �� Orientation$ 
Horizontal=�5      .+�5      �� $��Center=�5      $��16 0 0 0q�5      $��脆弱性選択��5      $��18(�5      5      5      �� 5   
   -   5         ��Name$ Sqlin��5      $!��SQLインジェクション��5       d� 	IsChecked$ FalseY�5      $
��Left=�5      $��210,100,0,0q�5      $	��Top=�5       $��16(�5!       2  .MaterialDesignFilterChipPrimaryOutlineCheckBox#��[  5"      �� 5$   
   -   5        $	 Xss��5$      $3��-クロスサイト・スクリプティング��5%      $ FalseY�5&      $
��Left=�5'      $��210,160,0,0q�5(      $	��Top=�5)      $��16(�5*      #��[  5+      �� 5-   
   -   5        $
 Csrf��5-      $
��CSRF��5.      $ FalseY�5/      $
��Left=�50      $��210,220,0,0q�51      $	��Top=�52      $��16(�53      #��[  54      �� 56   
   -   5        $ Oscmd��56      $/��)OSコマンド・インジェクション��57      $ FalseY�58      $
��Left=�59      $��210,280,0,0q�5:      $	��Top=�5;      $��16(�5<      #��[  5=      �� 5?   
   -   5        $
 Dirl��5?      $-��'ディレクトリ・リスティング��5@      $ falseY�5A      $
��Left=�5B      $��470,100,0,0q�5C      $	��Top=�5D      $��16(�5E      #��[  5F      �� 5H   
   -   5        $
 Dirt��5H      $-��'ディレクトリ・トラバーサル��5I      $ FalseY�5J      $
��Left=�5K      $��470,160,0,0q�5L      $	��Top=�5M      $��16(�5N      #��[  5O      �� 5Q   
   -   5        $	 Red��5Q      $'��!意図しないリダイレクト��5R      $ FalseY�5S      $
��Left=�5T      $��470,220,0,0q�5U      $	��Top=�5V      $��16(�5W      #��[  5X      �� 5Z   
   -	   5        $
 Http��5Z      $.��(HTTPヘッダ・インジェクション��5[      $ FalseY�5\      $
��Left=�5]      $��470,280,0,0q�5^      $	��Top=�5_      $��16(�5`      #��[  5a      �� 5c   
   -
   5        $��OK��5c      $
��Left=�5d      $��245,350,0,0q�5e      $	��Top=�5f      $��80��5g      $��25��5h        MaterialDesignPaperButton#��[ 5j       � ToolTip$. (Resource name: MaterialDesignPaperButton��5k      {�5l      �� *DataContext.ControlsEnabled+ �� RelativeSource �� *FindAncestor+ �� AncestorType$ WindowL��� 5n   
   -   5        $��戻る��5n      $
��Left=�5o      $��460,350,0,0q�5p      $	��Top=�5q      $��80��5r      $��25��5s      #��[ 5u      $. (Resource name: MaterialDesignPaperButton��5v      {�5w      �� *DataContext.ControlsEnabled+ �� *FindAncestor+$ WindowL�5z      5{      