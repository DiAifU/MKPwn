using System;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using WinFormPath = System.IO.Path;
using WinFormFile = System.IO.File;
using System.Reflection;
using CoreFoundation;
using Microsoft.Win32;
using System.Threading;
using Ionic.Zip;
using System.Security.Cryptography;
using System.IO;
using System.Diagnostics;
using System.Windows.Media.Animation;
using System.Runtime.InteropServices;
using System.Drawing;
using System.Windows.Threading;

namespace MKPwn
{
    /// <summary>
    /// Logique d'interaction pour MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        static string TEMP_PATH = WinFormPath.Combine(WinFormPath.GetTempPath(), @"MKPwn\");
        static string BUNDLES_PATH = WinFormPath.Combine(System.IO.Path.GetDirectoryName(Assembly.GetEntryAssembly().Location), "CustomPackages");
        static string FIRMWARE_BUNDLES_PATH = WinFormPath.Combine(WinFormPath.GetDirectoryName(Assembly.GetEntryAssembly().Location), "FirmwareBundles");
        static string FIRMWARE_EXTRACT_PATH = WinFormPath.Combine(TEMP_PATH, "IPSW");

        static string FirmwareSHA1 = null;
        static string FirmwareBundlePath = null;
        static CFDictionaryRef FirmwareBundleInfoNode = null;
        static string RootFSPath = null;
        static string DecryptedRootFS = null;
        static string RootFSKey = null;
        static string RestoreRamdiskPath = null;
        static bool IsUnziping = false;
        static int PartitionSize = 1024;
        static bool ActivatePhone = false, EnableHomeWallpaper = false, EnableMultitasking = false, EnableBatteryPercentage = false, AddPreInstalledPackages = true, UpdateBaseband = false;
        static string CustBootLgPath = null, CustRecovLgPath = null;
        public MainWindow()
        {
            InitializeComponent();
            try {
                Process[] processes = Process.GetProcessesByName("hfsplus");
                foreach (Process process in processes)
                    process.Kill();
                processes = Process.GetProcessesByName("dmg");
                foreach (Process process in processes)
                    process.Kill();
                processes = Process.GetProcessesByName("xpwntool");
                foreach (Process process in processes)
                    process.Kill();
            }
            catch { }


            if (Directory.Exists(TEMP_PATH))
                Directory.Delete(TEMP_PATH, true);
        }

        private delegate void IdentifyIPSWLabelUpdateDelegate(string text);
        private void IdentifyIPSWLabelUpdate(string text) { FirmLabel.Content = text; }

        private delegate void StatusLabelUpdateDelegate(string text);
        private void StatusLabelUpdate(string text) { StatusLabel.Content = text; }

        private delegate void EnableControlDelegate(Control ctrl, bool enabled);
        private void EnableControl(Control ctrl, bool enabled) { ctrl.IsEnabled = enabled; }

        private delegate void SetProgressBarValueDelegate(double value);
        private void SetProgressBarValue(double value)
        {
            Duration duration = new Duration(TimeSpan.FromMilliseconds(100));

            DoubleAnimation doubleanimation = new DoubleAnimation(value, duration);

            StatusProgressBar.BeginAnimation(ProgressBar.ValueProperty, doubleanimation);
        }

        private void RootFSSizeTextBox_PreviewTextInput(object sender, TextCompositionEventArgs e)
        {
            e.Handled = !ValidNumeric(e.Text);
            base.OnPreviewTextInput(e);
        }
        bool ValidNumeric(string str)
        {
            bool ret = true;
            for (int i = 0; i < str.Length; i++)
            {
                char ch = str[i];
                ret &= Char.IsDigit(ch);
            }
            return ret;
        }

        private delegate void ResetUIHandler();
        private void ResetUI()
        {
            FirmLabel.Content = "No firmware selected";
            BrowseFirmButton.IsEnabled = true;
            BuildButton.IsEnabled = false;
            MainOptionsGroupBox.IsEnabled = true;
            OtherOptionsGroupBox.IsEnabled = true;
            ActivCheckBox.IsEnabled = false;
            ActivCheckBox.IsChecked = false;
            MultitaskCheckBox.IsEnabled = false;
            MultitaskCheckBox.IsChecked = false;
            WallpaperCheckBox.IsEnabled = false;
            WallpaperCheckBox.IsChecked = false;
            BattPercCheckBox.IsEnabled = false;
            BattPercCheckBox.IsChecked = false;
            CustBootLgCheckBox.IsEnabled = false;
            CustBootLgCheckBox.IsChecked = false;
            CustRecovLgCheckBox.IsEnabled = false;
            CustRecovLgCheckBox.IsChecked = false;
            PreInstalledPackagesCheckBox.IsChecked = true;
            RootFSSizeTextBox.Text = "1024";
            StatusLabel.Content = "Not working";
            FirmwareSHA1 = null;
            FirmwareBundlePath = null;
            FirmwareBundleInfoNode = null;
            RootFSPath = null;
            DecryptedRootFS = null;
            RootFSKey = null;
            RestoreRamdiskPath = null;
            IsUnziping = false;
            PartitionSize = 1024;
            ActivatePhone = false;
            EnableHomeWallpaper = false;
            EnableMultitasking = false;
            EnableBatteryPercentage = false;
            AddPreInstalledPackages = true;
            CustBootLgPath = null;
            CustRecovLgPath = null;
            SetProgressBarValue(0.0);
        }

        static void ParseAndExecuteAction(CFDictionaryRef action)
        {
            string Action = action.GetValue("Action").ToString();
            if (Action == "Add")
            {
                string localPath = WinFormPath.Combine(FirmwareBundlePath, action.GetValue("File").ToString());
                string remotePath = "/" + action.GetValue("Path").ToString();
                bool alreadyExists = Pwn.hfsplus_FileExists(DecryptedRootFS, remotePath);
                if (alreadyExists)
                {
                    if (remotePath == "/sbin/launchd")
                        Pwn.hfsplus_mv(DecryptedRootFS, remotePath, "/sbin/crunchd");
                    else
                        Pwn.hfsplus_mv(DecryptedRootFS, remotePath, remotePath + "_orig");
                }
                Pwn.hfsplus_add(DecryptedRootFS, localPath, remotePath);
                if (alreadyExists)
                {
                    if (remotePath != "/sbin/launchd")
                    {
                        Pwn.hfsplus_chown(DecryptedRootFS, remotePath, Pwn.hfsplus_GETowner(DecryptedRootFS, remotePath + "_orig"), Pwn.hfsplus_GETgroup(DecryptedRootFS, remotePath + "_orig"));
                        Pwn.hfsplus_chmod(DecryptedRootFS, remotePath, Pwn.hfsplus_GETchmod(DecryptedRootFS, remotePath + "_orig"));
                    }
                }
            }
            else if (Action == "Patch")
            {
                string remotePath = "/" + action.GetValue("File").ToString();
                string localPath = WinFormPath.Combine(FIRMWARE_EXTRACT_PATH, WinFormPath.GetFileName(action.GetValue("File").ToString()));
                string localPathPatched = localPath + ".patched";
                string patchPath = WinFormPath.Combine(FirmwareBundlePath, action.GetValue("Patch").ToString());
                Pwn.hfsplus_extract(DecryptedRootFS, remotePath, localPath);
                if (!File.Exists(localPath))
                {
                    Console.WriteLine("ERROR: Unable to extract " + remotePath + " from Root Filesystem");
                    return;
                }
                Pwn.bspatch(localPath, localPathPatched, patchPath);
                if (!File.Exists(localPathPatched))
                {
                    Console.WriteLine("ERROR: Unable to patch " + WinFormPath.GetFileName(localPath));
                    return;
                }
                Pwn.hfsplus_mv(DecryptedRootFS, remotePath, remotePath + "_orig");
                Pwn.hfsplus_add(DecryptedRootFS, localPathPatched, remotePath);
                Pwn.hfsplus_chown(DecryptedRootFS, remotePath, Pwn.hfsplus_GETowner(DecryptedRootFS, remotePath + "_orig"), Pwn.hfsplus_GETgroup(DecryptedRootFS, remotePath + "_orig"));
                Pwn.hfsplus_chmod(DecryptedRootFS, remotePath, Pwn.hfsplus_GETchmod(DecryptedRootFS, remotePath + "_orig"));
                File.Delete(localPath);
                File.Delete(localPathPatched);
            }
            else if (Action == "SetPermission")
            {
                string remoteFile = "/" + action.GetValue("File").ToString();
                string permission = action.GetValue("Permission").ToString();
                Pwn.hfsplus_chmod(DecryptedRootFS, remoteFile, permission.Length == 3 ? "100" + permission : permission);
            }
            else if (Action == "SetOwner")
            {
                string remoteFile = "/" + action.GetValue("File").ToString();
                string owner = action.GetValue("Owner").ToString();
                Pwn.hfsplus_chown(DecryptedRootFS, remoteFile, owner.Split(':')[0], owner.Split(':')[1]);

            }
            else if (Action == "ReplaceKernel")
            {
                string remotePath = "/" + action.GetValue("Path").ToString();
                string localPath = WinFormPath.Combine(FIRMWARE_EXTRACT_PATH, WinFormPath.GetFileName(action.GetValue("File").ToString()));
                Pwn.hfsplus_mv(DecryptedRootFS, remotePath, remotePath + "_orig");
                Pwn.hfsplus_add(DecryptedRootFS, localPath, remotePath);
                Pwn.hfsplus_chown(DecryptedRootFS, remotePath, Pwn.hfsplus_GETowner(DecryptedRootFS, remotePath + "_orig"), Pwn.hfsplus_GETgroup(DecryptedRootFS, remotePath + "_orig"));
                Pwn.hfsplus_chmod(DecryptedRootFS, remotePath, Pwn.hfsplus_GETchmod(DecryptedRootFS, remotePath + "_orig"));

            }
            if (action.ContainsKey("MoreActions"))
            {
                foreach (CFDictionaryRef moreAction in ((CFArrayRef)action.GetValue("MoreActions")).Values)
                    ParseAndExecuteAction(moreAction);
            }
            
        }


        private void OptionsCheckedChange(object sender, RoutedEventArgs e)
        {
            if (e.Source == ActivCheckBox)
                ActivatePhone = ActivCheckBox.IsChecked.HasValue ? ActivCheckBox.IsChecked.Value : false;
            else if (e.Source == WallpaperCheckBox)
                EnableHomeWallpaper = WallpaperCheckBox.IsChecked.HasValue ? WallpaperCheckBox.IsChecked.Value : false;
            else if (e.Source == BattPercCheckBox)
                EnableBatteryPercentage = BattPercCheckBox.IsChecked.HasValue ? BattPercCheckBox.IsChecked.Value : false;
            else if (e.Source == MultitaskCheckBox)
                EnableMultitasking = MultitaskCheckBox.IsChecked.HasValue ? MultitaskCheckBox.IsChecked.Value : false;
            else if (e.Source == PreInstalledPackagesCheckBox)
                AddPreInstalledPackages = PreInstalledPackagesCheckBox.IsChecked.HasValue ? PreInstalledPackagesCheckBox.IsChecked.Value : false;
            else if (e.Source == UpdateBasebandCheckBox)
                UpdateBaseband = UpdateBasebandCheckBox.IsChecked.HasValue ? UpdateBasebandCheckBox.IsChecked.Value : false;
        }

        private void LogosCheckBoxes_Checked(object sender, RoutedEventArgs e)
        {
            if (e.Source == CustBootLgCheckBox)
            {
                if (CustBootLgCheckBox.IsChecked.HasValue && CustBootLgCheckBox.IsChecked.Value)
                {
                    OpenFileDialog BLogoBrowser = new OpenFileDialog();
                    BLogoBrowser.DefaultExt = ".png";
                    BLogoBrowser.Filter = "PNG file (.png)|*.png";
                    BLogoBrowser.Title = "Browse for your boot logo...";
                    while (CustBootLgPath == null)
                    {
                        bool? Value = BLogoBrowser.ShowDialog();
                        if (Value.HasValue && Value.Value)
                        {
                            CustBootLgPath = BLogoBrowser.FileName;
                            using (System.Drawing.Image img = Bitmap.FromFile(CustBootLgPath))
                            {
                                if (img.Width > 320 || img.Height > 480 || new FileInfo(CustBootLgPath).Length > 100000)
                                {
                                    MessageBox.Show("Error :  Either you PNG is not 320x480 or it is more than 100kb", "MKPwn", MessageBoxButton.OK, MessageBoxImage.Error);
                                    CustBootLgPath = null;
                                }
                                else break;
                            }
                        }
                        else
                        {
                            CustBootLgCheckBox.IsChecked = false;
                            break;
                        }
                    }
                }
                else
                    CustBootLgPath = null;
            }
            else if (e.Source == CustRecovLgCheckBox)
            {
                if (CustRecovLgCheckBox.IsChecked.HasValue && CustRecovLgCheckBox.IsChecked.Value)
                {
                    OpenFileDialog BRecovBrowser = new OpenFileDialog();
                    BRecovBrowser.DefaultExt = ".png";
                    BRecovBrowser.Filter = "PNG file (.png)|*.png";
                    BRecovBrowser.Title = "Browse for your recovery logo...";
                    while (CustRecovLgPath == null)
                    {
                        bool? Value = BRecovBrowser.ShowDialog();
                        if (Value.HasValue && Value.Value)
                        {
                            CustRecovLgPath = BRecovBrowser.FileName;
                            using (System.Drawing.Image img = Bitmap.FromFile(CustRecovLgPath))
                            {
                                if (img.Width > 320 || img.Height > 480 || new FileInfo(CustRecovLgPath).Length > 100000)
                                {
                                    MessageBox.Show("Error :  Either you PNG is not 320x480 or it is more than 100kb", "MKPwn", MessageBoxButton.OK, MessageBoxImage.Error);
                                    CustRecovLgPath = null;
                                }
                                else break;
                            }
                        }
                        else
                        {
                            CustRecovLgCheckBox.IsChecked = false;
                            break;
                        }
                    }
                }
                else
                    CustRecovLgPath = null;
            }
        }


        [DllImport("user32.dll")]
        public static extern int GetKeyboardState(byte[] keystate);
        private void MainWindow_KeyDown(object sender, KeyEventArgs e)
        {
            byte[] keys = new byte[255];
            GetKeyboardState(keys);
            if (keys[(int)System.Windows.Forms.Keys.D] == 129 && keys[(int)System.Windows.Forms.Keys.E] == 129 && keys[(int)System.Windows.Forms.Keys.B] == 129 && keys[(int)System.Windows.Forms.Keys.U] == 129 && keys[(int)System.Windows.Forms.Keys.G] == 129)
            {
                PreInstalledPackagesCheckBox.Visibility = Visibility.Visible;
                UpdateBasebandCheckBox.Visibility = Visibility.Visible;
            }
        }

        private void Window_Closing(object sender, System.ComponentModel.CancelEventArgs e)
        {
            if (Directory.Exists(TEMP_PATH))
                Directory.Delete(TEMP_PATH, true);
        }

        private void BrowseFirmButton_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog BrowseFirmware = new OpenFileDialog();
            BrowseFirmware.DefaultExt = ".ipsw";
            BrowseFirmware.Filter = "Apple Firmware (.ipsw)|*.ipsw";
            BrowseFirmware.Title = "Browse for your firmware...";
            bool? Value = BrowseFirmware.ShowDialog();
            if (Value.HasValue && Value.Value)
            {
                BrowseFirmButton.IsEnabled = false;
                Thread IdentifyIPSWThread = new Thread(new ParameterizedThreadStart(IdentifyIPSW));
                IdentifyIPSWThread.Priority = ThreadPriority.Highest;
                IdentifyIPSWThread.SetApartmentState(ApartmentState.STA);
                IdentifyIPSWThread.Start(BrowseFirmware.FileName);
            }
        }

        private void IdentifyIPSW(object file)
        {
            string path = (string)file;

            Dispatcher.Invoke(DispatcherPriority.Normal,new IdentifyIPSWLabelUpdateDelegate(IdentifyIPSWLabelUpdate), "Reading firmware data...");
            FileStream data = new FileStream(path, FileMode.Open);
            Dispatcher.Invoke(DispatcherPriority.Normal,new IdentifyIPSWLabelUpdateDelegate(IdentifyIPSWLabelUpdate), "Getting Firmware Bundle...");
            FirmwareSHA1 = BitConverter.ToString(new SHA1CryptoServiceProvider().ComputeHash(data)).Replace("-", "").ToLower();
            foreach (string bundle in Directory.GetDirectories(FIRMWARE_BUNDLES_PATH))
            {
                string InfoBundle = WinFormPath.Combine(bundle, "Info.plist");
                if (!WinFormFile.Exists(InfoBundle))
                {
                    Console.WriteLine("Bundle " + WinFormPath.GetFileName(bundle) + " is invalid !");
                    continue;
                }
                FirmwareBundleInfoNode = (CFDictionaryRef)CFPropertyListRef.CreateWithData(new CFDataRef(WinFormFile.ReadAllBytes(InfoBundle)), CFPropertyListMutabilityOptions.kCFPropertyListImmutable);
                if (FirmwareBundleInfoNode.GetValue("SHA1").ToString() == FirmwareSHA1)
                {
                    FirmwareBundlePath = bundle;
                    break;
                }
            }
            if (FirmwareBundlePath == null)
            {
                Dispatcher.Invoke(DispatcherPriority.Normal,new IdentifyIPSWLabelUpdateDelegate(IdentifyIPSWLabelUpdate), "ERROR: Unable to find Firmware bundle for you IPSW !");
                Dispatcher.Invoke(DispatcherPriority.Normal,new EnableControlDelegate(EnableControl), BrowseFirmButton, true);
                return;
            }
            data.Close();

            if (FirmwareBundleInfoNode.ContainsKey("FilesystemPatches") && ((CFDictionaryRef)FirmwareBundleInfoNode.GetValue("FilesystemPatches")).ContainsKey("Phone Activation"))
                Dispatcher.Invoke(DispatcherPriority.Normal,new EnableControlDelegate(EnableControl), ActivCheckBox, true);
            string FunctionalityPlist = FirmwareBundleInfoNode.ContainsKey("FunctionalityPlist") ? FirmwareBundleInfoNode.GetValue("FunctionalityPlist").ToString() : null;
            if (FunctionalityPlist != null)
            {
                if (FirmwareBundleInfoNode.ContainsKey("SupportBatteryPercentage") && ((CFBooleanRef)FirmwareBundleInfoNode.GetValue("SupportBatteryPercentage")).Value)
                    Dispatcher.Invoke(DispatcherPriority.Normal,new EnableControlDelegate(EnableControl), BattPercCheckBox, true);
                if (FirmwareBundleInfoNode.ContainsKey("SupportMultitasking") && ((CFBooleanRef)FirmwareBundleInfoNode.GetValue("SupportMultitasking")).Value)
                    Dispatcher.Invoke(DispatcherPriority.Normal,new EnableControlDelegate(EnableControl), MultitaskCheckBox, true);
                if (FirmwareBundleInfoNode.ContainsKey("SupportWallpaper") && ((CFBooleanRef)FirmwareBundleInfoNode.GetValue("SupportWallpaper")).Value)
                    Dispatcher.Invoke(DispatcherPriority.Normal,new EnableControlDelegate(EnableControl), WallpaperCheckBox, true);
                if (FirmwareBundleInfoNode.ContainsKey("SupportCustomLogos") && ((CFBooleanRef)FirmwareBundleInfoNode.GetValue("SupportCustomLogos")).Value)
                {
                    Dispatcher.Invoke(DispatcherPriority.Normal,new EnableControlDelegate(EnableControl), CustBootLgCheckBox, true);
                    Dispatcher.Invoke(DispatcherPriority.Normal,new EnableControlDelegate(EnableControl), CustRecovLgCheckBox, true);
                }
            }
            Dispatcher.Invoke(DispatcherPriority.Normal,new EnableControlDelegate(EnableControl), BuildButton, true);
            Dispatcher.Invoke(DispatcherPriority.Normal,new IdentifyIPSWLabelUpdateDelegate(IdentifyIPSWLabelUpdate), "Unzipping firmware...");
            try
            {
                using (ZipFile IPSWZIP = ZipFile.Read(path))
                {
                    IsUnziping = true;
                    IPSWZIP.ExtractAll(FIRMWARE_EXTRACT_PATH, ExtractExistingFileAction.OverwriteSilently);
                    IPSWZIP.Dispose();
                    IsUnziping = false;
                }
            }
            catch
            {
                IsUnziping = false;
                Dispatcher.Invoke(DispatcherPriority.Normal,new IdentifyIPSWLabelUpdateDelegate(IdentifyIPSWLabelUpdate), "ERROR: Unable to unzip firmware.");
                Dispatcher.Invoke(DispatcherPriority.Normal,new EnableControlDelegate(EnableControl), BrowseFirmButton, true);
                return;
            }
            Dispatcher.Invoke(DispatcherPriority.Normal,new IdentifyIPSWLabelUpdateDelegate(IdentifyIPSWLabelUpdate), "Firmware Bundle founded : " + WinFormPath.GetFileName(FirmwareBundlePath));

            if (FirmwareBundleInfoNode.ContainsKey("DeleteBuildManifest") && ((CFBooleanRef)FirmwareBundleInfoNode.GetValue("DeleteBuildManifest")).Value)
            {
                string BuildManifestPath = WinFormPath.Combine(FIRMWARE_EXTRACT_PATH, "BuildManifest.plist");
                if (File.Exists(BuildManifestPath))
                    File.Delete(BuildManifestPath);
            }
        }

        private void BuildButton_Click(object sender, RoutedEventArgs e)
        {
            PartitionSize = Int32.Parse(RootFSSizeTextBox.Text);
            BuildButton.IsEnabled = false;
            MainOptionsGroupBox.IsEnabled = false;
            OtherOptionsGroupBox.IsEnabled = false;
            Thread IdentifyIPSWThread = new Thread(new ThreadStart(BuildIt));
            IdentifyIPSWThread.Priority = ThreadPriority.Highest;
            IdentifyIPSWThread.SetApartmentState(ApartmentState.STA);
            IdentifyIPSWThread.Start();
        }


        private void BuildIt()
        {
            double ProgressValue = 10.0;
            if (IsUnziping)
            {
                Dispatcher.Invoke(DispatcherPriority.Normal,new StatusLabelUpdateDelegate(StatusLabelUpdate), "Waiting for unzip to finish...");
                while (IsUnziping)
                {

                }
            }
            Dispatcher.Invoke(DispatcherPriority.Normal,new SetProgressBarValueDelegate(SetProgressBarValue), ProgressValue);
            Dispatcher.Invoke(DispatcherPriority.Normal,new StatusLabelUpdateDelegate(StatusLabelUpdate), "Extracting resources...");
            ZipFile.Read(Properties.Resources.resources).ExtractAll(TEMP_PATH, ExtractExistingFileAction.OverwriteSilently);
            CFDictionaryRef FirmwarePatches = (CFDictionaryRef)FirmwareBundleInfoNode.GetValue("FirmwarePatches");
            for (int i = 0; i < FirmwarePatches.Count; i++)
            {
                string key = FirmwarePatches.Keys[i].ToString();
                CFDictionaryRef FirmwarePatch = (CFDictionaryRef)FirmwarePatches.Values[i];
                string localPath = WinFormPath.Combine(FIRMWARE_EXTRACT_PATH, FirmwarePatch.GetValue("File").ToString().Replace("/", "\\"));
                string patchPath = null;
                if (FirmwarePatch.ContainsKey("Patch"))
                    patchPath = WinFormPath.Combine(FirmwareBundlePath, FirmwarePatch.GetValue("Patch").ToString().Replace("/", "\\"));

                if (key == "Update Ramdisk")
                {
                    File.Delete(localPath);
                    Dispatcher.Invoke(DispatcherPriority.Normal,new SetProgressBarValueDelegate(SetProgressBarValue), ProgressValue += 30.0 / (double)FirmwarePatches.Count);
                }
                else if (patchPath != null || key == "Restore Ramdisk")
                {
                    string localpathTemplate = localPath + ".template";
                    string localPathPatched = localPath + ".patched";
                    if (File.Exists(localpathTemplate))
                        File.Delete(localpathTemplate);
                    File.Move(localPath, localpathTemplate);
                    string IV = null;
                    string Key = null;
                    if (FirmwarePatch.ContainsKey("IV") && FirmwarePatch.ContainsKey("Key"))
                    {
                        IV = FirmwarePatch.GetValue("IV").ToString();
                        Key = FirmwarePatch.GetValue("Key").ToString();
                    }

                    Dispatcher.Invoke(DispatcherPriority.Normal,new StatusLabelUpdateDelegate(StatusLabelUpdate), "Decrypting " + key + "...");
                    Pwn.xpwntool(localpathTemplate, localPath, IV, Key);
                    Dispatcher.Invoke(DispatcherPriority.Normal,new SetProgressBarValueDelegate(SetProgressBarValue), ProgressValue += 10.0 / (double)FirmwarePatches.Count);
                    if (patchPath != null)
                    {
                        Dispatcher.Invoke(DispatcherPriority.Normal,new StatusLabelUpdateDelegate(StatusLabelUpdate), "    Patching " + key + "...");
                        Pwn.bspatch(localPath, localPathPatched, patchPath);
                        if (!File.Exists(localPathPatched))
                        {
                            Console.WriteLine("ERROR: Unable to patch " + WinFormPath.GetFileName(localPath));
                            return;
                        }
                        File.Delete(localPath);
                        File.Move(localPathPatched, localPath);
                        Dispatcher.Invoke(DispatcherPriority.Normal,new SetProgressBarValueDelegate(SetProgressBarValue), ProgressValue += 10.0 / (double)FirmwarePatches.Count);
                    }
                    if (key == "Restore Ramdisk")
                    {
                        RestoreRamdiskPath = localPath;
                        Dispatcher.Invoke(DispatcherPriority.Normal,new StatusLabelUpdateDelegate(StatusLabelUpdate), "Patching Ramdisk files...");
                        CFDictionaryRef RamdiskPatches = (CFDictionaryRef)FirmwareBundleInfoNode.GetValue("RamdiskPatches");
                        Pwn.hfsplus_grow(RestoreRamdiskPath, "27500000");
                        foreach (CFDictionaryRef RamdiskPatch in RamdiskPatches.Values)
                        {
                            string newremotePath = "/" + RamdiskPatch.GetValue("File").ToString();
                            string newlocalPath = WinFormPath.Combine(FIRMWARE_EXTRACT_PATH, newremotePath.Split('/')[newremotePath.Split('/').Length - 1]);
                            string newlocalPathPatched = newlocalPath + ".patched";
                            string newpatchPath = WinFormPath.Combine(FirmwareBundlePath, RamdiskPatch.GetValue("Patch").ToString().Replace("/", "\\"));
                            Pwn.hfsplus_extract(RestoreRamdiskPath, newremotePath, newlocalPath);
                            if (!File.Exists(newlocalPath))
                            {
                                Dispatcher.Invoke(DispatcherPriority.Normal,new StatusLabelUpdateDelegate(StatusLabelUpdate), "ERROR: Unable to extract " + newremotePath + " from Ramdisk");
                                return;
                            }
                            Pwn.bspatch(newlocalPath, newlocalPathPatched, newpatchPath);
                            if (!File.Exists(newlocalPathPatched))
                            {
                                Dispatcher.Invoke(DispatcherPriority.Normal,new StatusLabelUpdateDelegate(StatusLabelUpdate), "ERROR: Unable to patch " + WinFormPath.GetFileName(newlocalPath));
                                return;
                            }
                            bool alreadyExists = Pwn.hfsplus_FileExists(RestoreRamdiskPath, newremotePath);
                            if (alreadyExists)
                                Pwn.hfsplus_mv(RestoreRamdiskPath, newremotePath, newremotePath + "_orig");
                            Pwn.hfsplus_add(RestoreRamdiskPath, newlocalPathPatched, newremotePath);
                            if (alreadyExists)
                            {
                                Pwn.hfsplus_chown(RestoreRamdiskPath, newremotePath, Pwn.hfsplus_GETowner(RestoreRamdiskPath, newremotePath + "_orig"), Pwn.hfsplus_GETgroup(RestoreRamdiskPath, newremotePath + "_orig"));
                                Pwn.hfsplus_chmod(RestoreRamdiskPath, newremotePath, Pwn.hfsplus_GETchmod(RestoreRamdiskPath, newremotePath + "_orig"));
                            }
                            File.Delete(newlocalPath);
                            File.Delete(newlocalPathPatched);
                        }

                        string optionsLocalPath = WinFormPath.Combine(FIRMWARE_EXTRACT_PATH, "options.plist");
                        Pwn.hfsplus_extract(RestoreRamdiskPath, "/usr/local/share/restore/options.plist", optionsLocalPath);
                        CFMutableDictionaryRef optDict = (CFMutableDictionaryRef)CFPropertyListRef.CreateWithData(new CFDataRef(File.ReadAllBytes(optionsLocalPath)), CFPropertyListMutabilityOptions.kCFPropertyListMutableContainers);
                        optDict.AddValue("CreateFilesystemPartitions", new CFBooleanRef(true));
                        optDict.SetValue("SystemPartitionSize", new CFNumberRef(PartitionSize));
                        optDict.AddValue("UpdateBaseband", new CFBooleanRef(UpdateBaseband));
                        byte[] newOpt = optDict.CreateData(CFPropertyListFormat.kCFPropertyListXMLFormat_v1_0).Value;
                        File.WriteAllBytes(optionsLocalPath, newOpt);
                        Pwn.hfsplus_mv(RestoreRamdiskPath, "/usr/local/share/restore/options.plist", "/usr/local/share/restore/options.plist_orig");
                        Pwn.hfsplus_add(RestoreRamdiskPath, optionsLocalPath, "/usr/local/share/restore/options.plist");
                        Pwn.hfsplus_chown(RestoreRamdiskPath, "/usr/local/share/restore/options.plist", Pwn.hfsplus_GETowner(RestoreRamdiskPath, "/usr/local/share/restore/options.plist_orig"), Pwn.hfsplus_GETgroup(RestoreRamdiskPath, "/usr/local/share/restore/options.plist_orig"));
                        Pwn.hfsplus_chmod(RestoreRamdiskPath, "/usr/local/share/restore/options.plist", Pwn.hfsplus_GETchmod(RestoreRamdiskPath, "/usr/local/share/restore/options.plist_orig"));
                        File.Delete(optionsLocalPath);
                        Pwn.hfsplus_add(RestoreRamdiskPath, WinFormPath.Combine(TEMP_PATH, "Resources\\applelogo-1x.png"), "/usr/share/progressui/images-1x/applelogo.png");
                        Pwn.hfsplus_add(RestoreRamdiskPath, WinFormPath.Combine(TEMP_PATH, "Resources\\applelogo-2x.png"), "/usr/share/progressui/images-2x/applelogo.png");
                        Pwn.hfsplus_add(RestoreRamdiskPath, WinFormPath.Combine(TEMP_PATH, "Resources\\applelogo-appletv.png"), "/usr/share/progressui/images-AppleTV/applelogo.png");

                        Dispatcher.Invoke(DispatcherPriority.Normal,new SetProgressBarValueDelegate(SetProgressBarValue), ProgressValue += 10.0 / (double)FirmwarePatches.Count);
                    }
                    Dispatcher.Invoke(DispatcherPriority.Normal,new StatusLabelUpdateDelegate(StatusLabelUpdate), "Encrypting " + key + "...");
                    Pwn.xpwntool(localPath, localPath + ".new", localpathTemplate, IV, Key);
                    if (File.Exists(localPath))
                        File.Delete(localPath);
                    File.Move(localPath + ".new", localPath);
                    File.Delete(localpathTemplate);
                    Dispatcher.Invoke(DispatcherPriority.Normal,new SetProgressBarValueDelegate(SetProgressBarValue), ProgressValue += 10.0 / (double)FirmwarePatches.Count);
                }
                if ((key == "AppleLogo" && CustBootLgPath != null) || (key == "RecoveryMode" && CustRecovLgPath != null))
                {
                    if (key == "AppleLogo")
                    {
                        string localpathTemplate = localPath + ".template";
                        if (File.Exists(localpathTemplate))
                            File.Delete(localpathTemplate);
                        File.Move(localPath, localpathTemplate);
                        string IV = null;
                        string Key = null;
                        if (FirmwarePatch.ContainsKey("IV") && FirmwarePatch.ContainsKey("Key"))
                        {
                            IV = FirmwarePatch.GetValue("IV").ToString();
                            Key = FirmwarePatch.GetValue("Key").ToString();
                        }
                        Pwn.imagetool_inject(CustBootLgPath, localPath, localpathTemplate, IV, Key);
                    }
                    else if (key == "RecoveryMode")
                    {
                        string localpathTemplate = localPath + ".template";
                        if (File.Exists(localpathTemplate))
                            File.Delete(localpathTemplate);
                        File.Move(localPath, localpathTemplate);
                        string IV = null;
                        string Key = null;
                        if (FirmwarePatch.ContainsKey("IV") && FirmwarePatch.ContainsKey("Key"))
                        {
                            IV = FirmwarePatch.GetValue("IV").ToString();
                            Key = FirmwarePatch.GetValue("Key").ToString();
                        }
                        Pwn.imagetool_inject(CustRecovLgPath, localPath, localpathTemplate, IV, Key);
                    }
                }

            }

            Dispatcher.Invoke(DispatcherPriority.Normal,new StatusLabelUpdateDelegate(StatusLabelUpdate), "Decrypting Root Filesystem...");
            if (!FirmwareBundleInfoNode.ContainsKey("RootFilesystem"))
            {
                Dispatcher.Invoke(DispatcherPriority.Normal,new StatusLabelUpdateDelegate(StatusLabelUpdate), "ERROR: Unable to find Root Filesystem");
                return;
            }
            RootFSPath = WinFormPath.Combine(FIRMWARE_EXTRACT_PATH, FirmwareBundleInfoNode.GetValue("RootFilesystem").ToString());
            DecryptedRootFS = WinFormPath.Combine(FIRMWARE_EXTRACT_PATH, "rootfs.hfs");

            if (!FirmwareBundleInfoNode.ContainsKey("RootFilesystemKey"))
            {
                Dispatcher.Invoke(DispatcherPriority.Normal,new StatusLabelUpdateDelegate(StatusLabelUpdate), "ERROR: Unable to find Root Filesystem decrypt key");
                return;
            }
            RootFSKey = FirmwareBundleInfoNode.GetValue("RootFilesystemKey").ToString();

            Pwn.dmg_extract(RootFSPath, DecryptedRootFS, RootFSKey);

            if (!File.Exists(DecryptedRootFS) || new FileInfo(DecryptedRootFS).Length <= 0)
            {
                Dispatcher.Invoke(DispatcherPriority.Normal,new StatusLabelUpdateDelegate(StatusLabelUpdate), "ERROR: Unable to decrypt Root Filesystem");
                return;
            }

            Pwn.hfsplus_grow(DecryptedRootFS, (Convert.ToDouble(FirmwareBundleInfoNode.GetValue("RootFilesystemSize").ToString()) * 1048576.0).ToString());
            Dispatcher.Invoke(DispatcherPriority.Normal,new SetProgressBarValueDelegate(SetProgressBarValue), ProgressValue += 10.0);

            Dispatcher.Invoke(DispatcherPriority.Normal,new StatusLabelUpdateDelegate(StatusLabelUpdate), "Patching Root Filesystem...");
            CFDictionaryRef FilesystemPatches = (CFDictionaryRef)FirmwareBundleInfoNode.GetValue("FilesystemPatches");

            for (int i = 0; i < FilesystemPatches.Count; i++)
            {
                string key = FilesystemPatches.Keys[i].ToString();
                if (key == "Phone Activation")
                {
                    if (ActivatePhone)
                    {
                        CFArrayRef PhoneActivation = (CFArrayRef)FilesystemPatches.GetValue("Phone Activation");
                        foreach (CFDictionaryRef inst in PhoneActivation.Values)
                            ParseAndExecuteAction(inst);
                        Pwn.hfsplus_untar(DecryptedRootFS, WinFormPath.Combine(BUNDLES_PATH, "youtube.tar"));
                    }
                }
                else
                {
                    CFArrayRef PatchArray = (CFArrayRef)FilesystemPatches.Values[i];
                    foreach (CFDictionaryRef inst in PatchArray.Values)
                        ParseAndExecuteAction(inst);
                }
            }

            if (AddPreInstalledPackages)
            {
                Dispatcher.Invoke(DispatcherPriority.Normal,new StatusLabelUpdateDelegate(StatusLabelUpdate), "Adding Packages...");
                CFArrayRef PreInstalledPackages = (CFArrayRef)FirmwareBundleInfoNode.GetValue("PreInstalledPackages");
                foreach (CFStringRef package in PreInstalledPackages.Values)
                {
                    string packagePath = WinFormPath.Combine(BUNDLES_PATH, package.ToString() + ".zip");
                    if (!File.Exists(packagePath))
                    {
                        if (MessageBox.Show(package.ToString() + " can't be founded ! Would you like to continue without installing it ?", "Error", MessageBoxButton.YesNo, MessageBoxImage.Exclamation) == MessageBoxResult.Yes)
                            continue;
                        else
                            return;
                    }
                    ZipFile.Read(packagePath).ExtractAll(TEMP_PATH, ExtractExistingFileAction.OverwriteSilently);
                    Pwn.hfsplus_untar(DecryptedRootFS, WinFormPath.Combine(TEMP_PATH, "Package.tar"));
                    File.Delete(WinFormPath.Combine(TEMP_PATH, "Package.tar"));
                }
            }

            if (FirmwareBundleInfoNode.ContainsKey("FunctionalityPlist") && (EnableMultitasking || EnableBatteryPercentage || EnableHomeWallpaper))
            {
                string remotePath = "/" + FirmwareBundleInfoNode.GetValue("FunctionalityPlist").ToString();
                string localPath = WinFormPath.Combine(FIRMWARE_EXTRACT_PATH, remotePath.Split('/')[remotePath.Split('/').Length - 1]);
                Pwn.hfsplus_extract(DecryptedRootFS, remotePath, localPath);
                if (!WinFormFile.Exists(localPath))
                {
                    Dispatcher.Invoke(DispatcherPriority.Normal,new StatusLabelUpdateDelegate(StatusLabelUpdate), "ERROR: Unable to find " + remotePath + " in Root filesystem");
                    return;
                }
                CFMutableDictionaryRef FunctionalityPlistNode = (CFMutableDictionaryRef)CFPropertyListRef.CreateWithData(new CFDataRef(File.ReadAllBytes(localPath)), CFPropertyListMutabilityOptions.kCFPropertyListMutableContainersAndLeaves);
                CFMutableDictionaryRef capabilitiesNode = (CFMutableDictionaryRef)FunctionalityPlistNode.GetValue("capabilities");
                if (EnableMultitasking)
                    capabilitiesNode.SetValue("multitasking", new CFBooleanRef(true));
                if (EnableBatteryPercentage)
                    capabilitiesNode.SetValue("gas-gauge-battery", new CFBooleanRef(true));
                if (EnableHomeWallpaper)
                    capabilitiesNode.SetValue("homescreen-wallpaper", new CFBooleanRef(true));
                FunctionalityPlistNode.SetValue("capabilities", capabilitiesNode);
                File.WriteAllBytes(localPath, FunctionalityPlistNode.CreateData(CFPropertyListFormat.kCFPropertyListBinaryFormat_v1_0).Value);
                Pwn.hfsplus_mv(DecryptedRootFS, remotePath, remotePath + "_orig");
                Pwn.hfsplus_add(DecryptedRootFS, localPath, remotePath);
                Pwn.hfsplus_chown(DecryptedRootFS, remotePath, Pwn.hfsplus_GETowner(DecryptedRootFS, remotePath + "_orig"), Pwn.hfsplus_GETgroup(DecryptedRootFS, remotePath + "_orig"));
                Pwn.hfsplus_chmod(DecryptedRootFS, remotePath, Pwn.hfsplus_GETchmod(DecryptedRootFS, remotePath + "_orig"));
                File.Delete(localPath);

            }

            Dispatcher.Invoke(DispatcherPriority.Normal,new SetProgressBarValueDelegate(SetProgressBarValue), ProgressValue += 10.0);

            Dispatcher.Invoke(DispatcherPriority.Normal,new StatusLabelUpdateDelegate(StatusLabelUpdate), "Rebuilding Root Filesystem...");
            File.Delete(RootFSPath);
            Pwn.dmg_build(DecryptedRootFS, RootFSPath);
            File.Delete(DecryptedRootFS);

            Dispatcher.Invoke(DispatcherPriority.Normal,new SetProgressBarValueDelegate(SetProgressBarValue), ProgressValue += 20.0);
            string FirmName = FirmwareBundleInfoNode.GetValue("Name").ToString();
            string DeviceType = FirmName.Split('_')[0].Remove(FirmName.Split('_')[0].Length - 3);
            Dispatcher.Invoke(DispatcherPriority.Normal,new StatusLabelUpdateDelegate(StatusLabelUpdate), "Saving firmware...");


            bool done = false;
            while (!done)
            {
                SaveFileDialog IPSWSaveDialog = new SaveFileDialog();
                IPSWSaveDialog.DefaultExt = ".ipsw";
                IPSWSaveDialog.Filter = "Apple Firmware (.ipsw)|*.ipsw";
                IPSWSaveDialog.FileName = FirmName + "_Custom_Restore.ipsw";
                bool? save = IPSWSaveDialog.ShowDialog();
                if (save.HasValue && save.Value)
                {
                    string CFirmPath = IPSWSaveDialog.FileName;
                    if (File.Exists(CFirmPath))
                        File.Delete(CFirmPath);
                    using (ZipFile zip = new ZipFile())
                    {
                        zip.AddDirectory(FIRMWARE_EXTRACT_PATH + "\\");
                        zip.Save(CFirmPath);
                    }
                    done = true;
                }
                else
                {
                    MessageBoxResult DontSave = MessageBox.Show("Do you really want to close without saving your firmware ?", "MKPwn", MessageBoxButton.YesNo, MessageBoxImage.Question);
                    if (DontSave == MessageBoxResult.Yes)
                        done = true;
                }
            }
            Dispatcher.Invoke(DispatcherPriority.Normal,new SetProgressBarValueDelegate(SetProgressBarValue), 100.0);
            Dispatcher.Invoke(DispatcherPriority.Normal,new StatusLabelUpdateDelegate(StatusLabelUpdate), "Done !");
            Thread.Sleep(3000);
            Dispatcher.Invoke(DispatcherPriority.Normal,new ResetUIHandler(ResetUI));
        }
    }
}
