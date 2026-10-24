using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace AES256
{
    public partial class Form1 : Form
    {
        private const int ChunkSize = 1024 * 1024 * 1024;   // 1 GiB processing block
        private const int SliceSize = 16 * 1024 * 1024;     // progress granularity inside a block
        private const long Fat32MaxFile = 4294967295L;      // 4 GiB - 1
        private const string Ext = ".aes256";
        private const string Version = "AES256 v2.0";

        // Set your salt here, change it to meet your flavor:
        // The salt bytes must be at least 8 bytes.
        // Changing it makes previously encrypted files undecryptable.
        private readonly byte[] saltBytes = new byte[] { 0xe9, 0x6c, 0xcf, 0x45, 0xe9, 0x6c, 0xcf, 0x45 }; // CRC32 for space twice

        private bool busy;

        private sealed class Job
        {
            public string Input;
            public string Output;
            public long Size;
        }

        private sealed class ProgressInfo
        {
            public int FileIndex;
            public int FileCount;
            public string FileName;
            public long FileDone;
            public long FileTotal;
            public long AllDone;
            public long AllTotal;
        }

        public Form1()
        {
            InitializeComponent();
            Text = Version;
        }

        // ---------- UI events ----------

        private void EncryptBtn_DragEnter(object sender, DragEventArgs e)
        {
            if (!busy && e.Data.GetDataPresent(DataFormats.FileDrop)) e.Effect = DragDropEffects.Copy;
        }

        private void DecryptBtn_DragEnter(object sender, DragEventArgs e)
        {
            if (!busy && e.Data.GetDataPresent(DataFormats.FileDrop)) e.Effect = DragDropEffects.Copy;
        }

        private void EncryptBtn_DragDrop(object sender, DragEventArgs e)
        {
            string[] files = (string[])e.Data.GetData(DataFormats.FileDrop);
            // Defer, so Explorer is not blocked by message boxes during drop
            BeginInvoke(new Action(() => Run(files, true)));
        }

        private void DecryptBtn_DragDrop(object sender, DragEventArgs e)
        {
            string[] files = (string[])e.Data.GetData(DataFormats.FileDrop);
            BeginInvoke(new Action(() => Run(files, false)));
        }

        private void EncryptBtn_Click(object sender, EventArgs e)
        {
            using (var ofd = new OpenFileDialog { Multiselect = true })
                if (ofd.ShowDialog() == DialogResult.OK)
                    Run(ofd.FileNames, true);
        }

        private void DecryptBtn_Click(object sender, EventArgs e)
        {
            using (var ofd = new OpenFileDialog { Multiselect = true, Filter = "AES256 files (*.aes256)|*.aes256|All files (*.*)|*.*" })
                if (ofd.ShowDialog() == DialogResult.OK)
                    Run(ofd.FileNames, false);
        }

        private void InfoBtn_Click(object sender, EventArgs e)
        {
            MessageBox.Show("AES256 file encrypter and decrypter\n© 2024-2026 pbies\n\nNo file size limit (files processed in 1 GiB blocks)\nSalt is always the same\nYou may click the buttons to select files\nor drag & drop files to buttons", Version);
        }

        private void Form1_FormClosing(object sender, FormClosingEventArgs e)
        {
            if (busy && e.CloseReason == CloseReason.UserClosing)
            {
                MessageBox.Show("Operation in progress. Wait until it finishes.", Version);
                e.Cancel = true;
            }
        }

        // ---------- orchestration ----------

        private async void Run(string[] files, bool encrypt)
        {
            if (busy || files == null || files.Length == 0) return;

            if (textBox1.Text.Length == 0)
            {
                MessageBox.Show("Enter password first.", Version);
                return;
            }
            string password = textBox1.Text;

            var jobs = new List<Job>();
            long allTotal = 0;
            foreach (string f in files)
            {
                string err;
                Job job = PrepareJob(f, encrypt, out err);
                if (job == null)
                {
                    if (err != null) MessageBox.Show(err + "\nFilename: " + f, Version);
                    continue;
                }
                jobs.Add(job);
                allTotal += job.Size;
            }
            if (jobs.Count == 0) return;

            SetBusy(true);
            var errors = new List<string>();
            var progress = new Progress<ProgressInfo>(p => UpdateProgress(p, encrypt));

            try
            {
                await Task.Run(() =>
                {
                    long allDoneBase = 0;
                    IProgress<ProgressInfo> rep = progress;
                    for (int i = 0; i < jobs.Count; i++)
                    {
                        Job job = jobs[i];
                        int idx = i;
                        long baseDone = allDoneBase;
                        int lastPermille = -1;
                        try
                        {
                            ProcessFile(job.Input, job.Output, password, encrypt, (done, total) =>
                            {
                                long all = baseDone + done;
                                int permille = allTotal == 0 ? 1000 : (int)(all * 1000 / allTotal);
                                if (permille == lastPermille && done != total) return;
                                lastPermille = permille;
                                rep.Report(new ProgressInfo
                                {
                                    FileIndex = idx + 1,
                                    FileCount = jobs.Count,
                                    FileName = Path.GetFileName(job.Input),
                                    FileDone = done,
                                    FileTotal = total,
                                    AllDone = all,
                                    AllTotal = allTotal
                                });
                            });
                        }
                        catch (CryptographicException) when (!encrypt)
                        {
                            lock (errors) errors.Add(job.Input + "\n  Wrong password or corrupted file.");
                        }
                        catch (Exception ex)
                        {
                            lock (errors) errors.Add(job.Input + "\n  " + ex.Message);
                        }
                        allDoneBase += job.Size;
                    }
                });
            }
            finally
            {
                SetBusy(false);
            }

            int ok = jobs.Count - errors.Count;
            statusLabel.Text = (encrypt ? "Encrypted " : "Decrypted ") + ok + "/" + jobs.Count + " file(s)";
            progressBar1.Value = progressBar1.Maximum;
            if (errors.Count > 0)
                MessageBox.Show(string.Join("\n\n", errors), Version + " - errors", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }

        private Job PrepareJob(string input, bool encrypt, out string err)
        {
            err = null;
            var fi = new FileInfo(input);
            if (!fi.Exists)
            {
                err = "File not found.";
                return null;
            }

            string output;
            long outSize;
            if (encrypt)
            {
                output = input + Ext;
                outSize = (fi.Length / 16 + 1) * 16; // PKCS7 always adds 1..16 bytes
            }
            else
            {
                if (!input.EndsWith(Ext, StringComparison.OrdinalIgnoreCase))
                {
                    err = "Not an " + Ext + " file.";
                    return null;
                }
                if (fi.Length == 0 || fi.Length % 16 != 0)
                {
                    err = "Corrupted file (size is not a multiple of 16 bytes).";
                    return null;
                }
                output = input.Substring(0, input.Length - Ext.Length);
                outSize = fi.Length;
            }

            try
            {
                string root = Path.GetPathRoot(Path.GetFullPath(output));
                var drive = new DriveInfo(root);
                if (encrypt && outSize > Fat32MaxFile && string.Equals(drive.DriveFormat, "FAT32", StringComparison.OrdinalIgnoreCase))
                {
                    err = "Output would exceed 4 GiB - 1 B, which FAT32 cannot store.";
                    return null;
                }
                if (drive.AvailableFreeSpace < outSize)
                {
                    err = "Not enough free space on " + root + " (" + FormatSize(outSize) + " needed).";
                    return null;
                }
            }
            catch (ArgumentException) { } // UNC/network paths: skip checks
            catch (IOException) { }

            if (File.Exists(output))
            {
                var r = MessageBox.Show("Output file exists:\n" + output + "\n\nOverwrite?", Version, MessageBoxButtons.YesNo, MessageBoxIcon.Warning);
                if (r != DialogResult.Yes) return null;
            }

            return new Job { Input = input, Output = output, Size = fi.Length };
        }

        private void SetBusy(bool value)
        {
            busy = value;
            EncryptBtn.Enabled = !value;
            DecryptBtn.Enabled = !value;
            textBox1.Enabled = !value;
            UseWaitCursor = value;
            if (value)
            {
                progressBar1.Value = 0;
                statusLabel.Text = "Starting...";
            }
        }

        private void UpdateProgress(ProgressInfo p, bool encrypt)
        {
            int v = p.AllTotal == 0 ? progressBar1.Maximum : (int)(p.AllDone * progressBar1.Maximum / p.AllTotal);
            progressBar1.Value = Math.Max(0, Math.Min(progressBar1.Maximum, v));
            int filePct = p.FileTotal == 0 ? 100 : (int)(p.FileDone * 100 / p.FileTotal);
            statusLabel.Text = string.Format("{0} {1}/{2}: {3}  {4}%  ({5} / {6})",
                encrypt ? "Encrypting" : "Decrypting",
                p.FileIndex, p.FileCount, p.FileName, filePct,
                FormatSize(p.FileDone), FormatSize(p.FileTotal));
        }

        private static string FormatSize(long bytes)
        {
            if (bytes >= 1L << 30) return (bytes / (double)(1L << 30)).ToString("0.00") + " GiB";
            if (bytes >= 1L << 20) return (bytes / (double)(1L << 20)).ToString("0.0") + " MiB";
            if (bytes >= 1L << 10) return (bytes / (double)(1L << 10)).ToString("0.0") + " KiB";
            return bytes + " B";
        }

        // ---------- crypto (output format unchanged vs v1.1) ----------

        private Aes CreateAes(string password)
        {
            byte[] passwordBytes;
            using (var sha = SHA256.Create())
                passwordBytes = sha.ComputeHash(Encoding.UTF8.GetBytes(password));

            Aes aes = Aes.Create();
            aes.KeySize = 256;
            aes.BlockSize = 128;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;
            using (var kdf = new Rfc2898DeriveBytes(passwordBytes, saltBytes, 1000))
            {
                aes.Key = kdf.GetBytes(aes.KeySize / 8);
                aes.IV = kdf.GetBytes(aes.BlockSize / 8);
            }
            return aes;
        }

        private void ProcessFile(string input, string output, string password, bool encrypt, Action<long, long> progress)
        {
            string tmp = output + ".part";
            try
            {
                using (Aes aes = CreateAes(password))
                using (ICryptoTransform transform = encrypt ? aes.CreateEncryptor() : aes.CreateDecryptor())
                using (var src = new FileStream(input, FileMode.Open, FileAccess.Read, FileShare.Read, 1 << 20, FileOptions.SequentialScan))
                using (var dst = new FileStream(tmp, FileMode.Create, FileAccess.Write, FileShare.None, 1 << 20))
                using (var cs = new CryptoStream(dst, transform, CryptoStreamMode.Write))
                {
                    long total = src.Length;
                    long done = 0;
                    byte[] buffer = new byte[(int)Math.Max(1, Math.Min(ChunkSize, total))];
                    progress(0, total);

                    int read;
                    while ((read = ReadBlock(src, buffer)) > 0)
                    {
                        for (int off = 0; off < read; off += SliceSize)
                        {
                            int n = Math.Min(SliceSize, read - off);
                            cs.Write(buffer, off, n);
                            done += n;
                            progress(done, total);
                        }
                    }
                    cs.FlushFinalBlock();
                }

                if (File.Exists(output)) File.Delete(output);
                File.Move(tmp, output);
            }
            catch
            {
                try { if (File.Exists(tmp)) File.Delete(tmp); } catch { }
                throw;
            }
        }

        // Fills the buffer completely unless EOF is reached
        private static int ReadBlock(Stream s, byte[] buffer)
        {
            int total = 0;
            while (total < buffer.Length)
            {
                int n = s.Read(buffer, total, buffer.Length - total);
                if (n == 0) break;
                total += n;
            }
            return total;
        }

        // ---------- borderless drag ----------

        public const int WM_NCLBUTTONDOWN = 0xA1;
        public const int HT_CAPTION = 0x2;

        [System.Runtime.InteropServices.DllImport("user32.dll")]
        public static extern int SendMessage(IntPtr hWnd, int Msg, int wParam, int lParam);
        [System.Runtime.InteropServices.DllImport("user32.dll")]
        public static extern bool ReleaseCapture();

        private void Form1_MouseDown(object sender, MouseEventArgs e)
        {
            if (e.Button == MouseButtons.Left)
            {
                ReleaseCapture();
                SendMessage(Handle, WM_NCLBUTTONDOWN, HT_CAPTION, 0);
            }
        }
    }
}
