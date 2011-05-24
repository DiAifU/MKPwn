using System;
using System.Collections.Generic;
using System.Text;
using System.Diagnostics;
using System.IO;
using System.Threading;
using System.Collections;
using System.Windows.Forms;

namespace MKPwn
{
    public static class Pwn
    {

        static string TEMP_PATH = Path.Combine(Path.GetTempPath(), @"MKPwn\");
        public static void ProcessStart(string fileName, string arguments)
        {


            Process proc = new Process();
            proc.StartInfo.WorkingDirectory = Path.GetDirectoryName(fileName);
            proc.StartInfo.FileName = fileName;
            proc.StartInfo.Arguments = arguments;
            proc.StartInfo.CreateNoWindow = true;
            proc.StartInfo.UseShellExecute = false;
            proc.Start();
            proc.WaitForExit();
        }

        static string QPath(string path)
        {
            return "\"" + path + "\"";
        }





        public static void dmg_extract(string encryptedVolumePath, string decryptedVolumePath, string key)
        {
            ProcessStart(Path.Combine(TEMP_PATH, @"Resources\dmg.exe"), "extract " + QPath(encryptedVolumePath) + " " + QPath(decryptedVolumePath) + " -k " + key);
        }

        public static void dmg_build(string decryptedVolumePath, string encryptedVolumePath)
        {
            ProcessStart(Path.Combine(TEMP_PATH, @"Resources\dmg.exe"), "build " + QPath(decryptedVolumePath) + " " + QPath(encryptedVolumePath));
        }

        public static void hfsplus_extract(string decryptedVolumePath, string remotePath, string localPath)
        {
            ProcessStart(Path.Combine(TEMP_PATH, @"Resources\hfsplus.exe"), QPath(decryptedVolumePath) + " extract  " + QPath(remotePath) + "  " + QPath(localPath));
        }

        public static void hfsplus_grow(string decryptedVolumePath, string sizeInBytes)
        {
            ProcessStart(Path.Combine(TEMP_PATH, @"Resources\hfsplus.exe"), QPath(decryptedVolumePath) + " grow " + sizeInBytes);
        }

        public static void hfsplus_add(string decryptedVolumePath, string localPath, string remotePath)
        {
            ProcessStart(Path.Combine(TEMP_PATH, @"Resources\hfsplus.exe"), QPath(decryptedVolumePath) + " add " + QPath(localPath) + " " + QPath(remotePath));
        }

        public static void hfsplus_mkdir(string decryptedVolumePath, string remotePath)
        {
            ProcessStart(Path.Combine(TEMP_PATH, @"Resources\hfsplus.exe"), QPath(decryptedVolumePath) + " mkdir " + QPath(remotePath));
        }

        public static void hfsplus_symlink(string decryptedVolumePath, string symlinkPath, string originalPath)
        {
            ProcessStart(Path.Combine(TEMP_PATH, @"Resources\hfsplus.exe"), QPath(decryptedVolumePath) + " symlink " + QPath(symlinkPath) + " " + QPath(originalPath));
        }

        public static void hfsplus_rm(string decryptedVolumePath, string remotePath)
        {
            ProcessStart(Path.Combine(TEMP_PATH, @"Resources\hfsplus.exe"), QPath(decryptedVolumePath) + " rm " + QPath(remotePath));
        }

        public static void hfsplus_mv(string decryptedVolumePath, string remotePath1, string remotePath2)
        {
            ProcessStart(Path.Combine(TEMP_PATH, @"Resources\hfsplus.exe"), QPath(decryptedVolumePath) + " mv " + QPath(remotePath1) + " " + QPath(remotePath2));
        }

        public static string hfsplus_GETchmod(string decryptedVolumePath, string remotePath)
        {
            Process proc = new Process();
            proc.StartInfo.Arguments = QPath(decryptedVolumePath) + " ls " + QPath(remotePath);
            proc.StartInfo.WorkingDirectory = Path.GetDirectoryName(Path.Combine(TEMP_PATH, @"Resources\hfsplus.exe"));
            proc.StartInfo.FileName = Path.Combine(TEMP_PATH, @"Resources\hfsplus.exe");
            proc.StartInfo.RedirectStandardOutput = true;
            proc.StartInfo.UseShellExecute = false;
            proc.StartInfo.CreateNoWindow = true;
            proc.Start();
            proc.WaitForExit();
            StreamReader output = proc.StandardOutput;
            output.ReadLine();
            foreach (string chmod in output.ReadLine().Split(' '))
            {
                if (!String.IsNullOrEmpty(chmod))
                {
                    output.Close();
                    return chmod;
                }
            }
            output.Close();
            return null;
        }

        public static void hfsplus_chmod(string decryptedVolumePath, string remotePath, string permission)
        {
            ProcessStart(Path.Combine(TEMP_PATH, @"Resources\hfsplus.exe"), QPath(decryptedVolumePath) + " chmod " + permission + " " + QPath(remotePath));
        }

        public static string hfsplus_GETowner(string decryptedVolumePath, string remotePath)
        {
            Process proc = new Process();
            proc.StartInfo.Arguments = QPath(decryptedVolumePath) + " ls " + QPath(remotePath);
            proc.StartInfo.WorkingDirectory = Path.GetDirectoryName(Path.Combine(TEMP_PATH, @"Resources\hfsplus.exe"));
            proc.StartInfo.FileName = Path.Combine(TEMP_PATH, @"Resources\hfsplus.exe");
            proc.StartInfo.RedirectStandardOutput = true;
            proc.StartInfo.UseShellExecute = false;
            proc.StartInfo.CreateNoWindow = true;
            proc.Start();
            proc.WaitForExit();
            StreamReader output = proc.StandardOutput;
            output.ReadLine();
            ArrayList infos = new ArrayList();
            foreach (string okok in output.ReadLine().Split(' '))
            {
                if (infos.Count == 3)
                    break;
                if (!String.IsNullOrEmpty(okok))
                    infos.Add(okok);
            }
            output.Close();
            return (string)infos[1];
        }

        public static string hfsplus_GETgroup(string decryptedVolumePath, string remotePath)
        {
            Process proc = new Process();
            proc.StartInfo.Arguments = QPath(decryptedVolumePath) + " ls " + QPath(remotePath);
            proc.StartInfo.WorkingDirectory = Path.GetDirectoryName(Path.Combine(TEMP_PATH, @"Resources\hfsplus.exe"));
            proc.StartInfo.FileName = Path.Combine(TEMP_PATH, @"Resources\hfsplus.exe");
            proc.StartInfo.RedirectStandardOutput = true;
            proc.StartInfo.UseShellExecute = false;
            proc.StartInfo.CreateNoWindow = true;
            proc.Start();
            proc.WaitForExit();
            StreamReader output = proc.StandardOutput;
            output.ReadLine();
            ArrayList infos = new ArrayList();
            foreach (string okok in output.ReadLine().Split(' '))
            {
                if (infos.Count == 3)
                    break;
                if (!String.IsNullOrEmpty(okok))
                    infos.Add(okok);
            }
            output.Close();
            return (string)infos[2];
        }

        public static void hfsplus_chown(string decryptedVolumePath, string remotePath, string owner, string group)
        {
            ProcessStart(Path.Combine(TEMP_PATH, @"Resources\hfsplus.exe"), QPath(decryptedVolumePath) + " chown " + owner + " " + group + " " + QPath(remotePath));
        }

        public static bool hfsplus_FileExists(string decryptedVolumePath, string remotePath)
        {
            Process proc = new Process();
            proc.StartInfo.Arguments = QPath(decryptedVolumePath) + " ls " + QPath(remotePath);
            proc.StartInfo.WorkingDirectory = Path.GetDirectoryName(Path.Combine(TEMP_PATH, @"Resources\hfsplus.exe"));
            proc.StartInfo.FileName = Path.Combine(TEMP_PATH, @"Resources\hfsplus.exe");
            proc.StartInfo.RedirectStandardOutput = true;
            proc.StartInfo.UseShellExecute = false;
            proc.StartInfo.CreateNoWindow = true;
            proc.Start();
            proc.WaitForExit();
            StreamReader output = proc.StandardOutput;
            if (output.ReadToEnd().Contains("No such file or directory"))
            {
                output.Close();
                return false;
            }
            else
            {
                return true;
            }
        }

        public static void hfsplus_untar(string decryptedVolumePath, string tarFile)
        {
            ProcessStart(Path.Combine(TEMP_PATH, @"Resources\hfsplus.exe"), QPath(decryptedVolumePath) + " untar " + QPath(tarFile));
        }

        public static void bspatch(string oldFile, string newFile, string patchFile)
        {
            ProcessStart(Path.Combine(TEMP_PATH, @"Resources\bspatch.exe"), QPath(oldFile) + " " + QPath(newFile) + " " + QPath(patchFile));
        }

        public static void xpwntool(string inFile, string outFile, string IV, string Key)
        {
            if (IV == null || Key == null)
                ProcessStart(Path.Combine(TEMP_PATH, @"Resources\xpwntool.exe"), QPath(inFile) + " " + QPath(outFile));
            else
            {
                ProcessStart(Path.Combine(TEMP_PATH, @"Resources\xpwntool.exe"), QPath(inFile) + " " + QPath(outFile) + " -iv " + IV + " -k " + Key);
            }
        }

        public static void xpwntool(string inFile, string outFile, string template, string IV, string Key)
        {
            if (IV == null || Key == null)
                ProcessStart(Path.Combine(TEMP_PATH, @"Resources\xpwntool.exe"), QPath(inFile) + " " + QPath(outFile) + " -t " + QPath(template));
            else
                ProcessStart(Path.Combine(TEMP_PATH, @"Resources\xpwntool.exe"), QPath(inFile) + " " + QPath(outFile) + " -t " + QPath(template) + " -iv " + IV + " -k " + Key);
        }

        public static void imagetool_inject(string imgPath, string outFile, string template, string IV, string Key)
        {
            if (IV == null || Key == null)
                ProcessStart(Path.Combine(TEMP_PATH, @"Resources\imagetool.exe"), "inject " +  QPath(imgPath) + " " + QPath(outFile) + " " + QPath(template));
            else
                ProcessStart(Path.Combine(TEMP_PATH, @"Resources\xpwntool.exe"), "inject " + QPath(imgPath) + " " + QPath(outFile) + " " + QPath(template) + " " + IV + " " + Key);
        }
    }
}

