using System;
using System.IO;
using System.Text;
using System.Collections.Generic;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Security.Cryptography;
using System.Threading;
using System.Web.Script.Serialization;

// One request per process. Encrypted vault envelopes and bounded device-key
// wrapping operations cross this boundary; no master password is received.
// No background service, file watcher, network access or password handling.
internal static class Host {
    const int Limit = 8000000;
    const string Origin = "chrome-extension://fgjoonbdgfdpjmpjbephffmkjackfgnp/";
    static readonly UTF8Encoding Utf8 = new UTF8Encoding(false, true);
    static readonly JavaScriptSerializer Json = new JavaScriptSerializer { MaxJsonLength = 20000000, RecursionLimit = 32 };
    static readonly byte[] DeviceEntropy = Encoding.UTF8.GetBytes("CHROME-APP-TOTP/device-key/v1");
    static Stream input, output;
    static byte[] ReadExact(int count) {
        byte[] bytes = new byte[count]; int offset = 0;
        while (offset < count) { int n = input.Read(bytes, offset, count - offset); if (n == 0) throw new IOException("Incomplete message"); offset += n; }
        return bytes;
    }
    static void Send(object value) {
        byte[] bytes = Utf8.GetBytes(Json.Serialize(value));
        if (bytes.Length > 1000000) throw new IOException("Message too large");
        byte[] prefix = BitConverter.GetBytes(bytes.Length); output.Write(prefix,0,4); output.Write(bytes,0,bytes.Length); output.Flush();
    }
    static string Text(Dictionary<string,object> d, string name) { object value; return d.TryGetValue(name,out value) ? value as string : null; }
    static string DefaultPath() {
        string home = Environment.GetEnvironmentVariable("USERPROFILE");
        if (String.IsNullOrWhiteSpace(home)) home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        return Path.Combine(home,".CHROME-APP-TOTP.vault");
    }
    static string ResolvePath(string value) {
        if (String.IsNullOrWhiteSpace(value)) value = DefaultPath();
        if (value.StartsWith("%USERPROFILE%\\",StringComparison.OrdinalIgnoreCase)) value = Path.Combine(Path.GetDirectoryName(DefaultPath()),value.Substring(14));
        if (value.Length < 4 || !Char.IsLetter(value[0]) || value[1] != ':' || value[2] != '\\' || value.IndexOf(':',2) >= 0) throw new Exception("Укажите полный локальный путь к файлу .vault или .json.");
        string full = Path.GetFullPath(value);
        string ext = Path.GetExtension(full);
        if (!ext.Equals(".vault",StringComparison.OrdinalIgnoreCase) && !ext.Equals(".json",StringComparison.OrdinalIgnoreCase)) throw new Exception("Файл должен иметь расширение .vault или .json.");
        foreach (string part in full.Substring(3).Split('\\')) {
            string stem = part.Split('.')[0].ToUpperInvariant();
            if (part.Length == 0 || part.EndsWith(" ") || part.EndsWith(".") || part.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0 || System.Text.RegularExpressions.Regex.IsMatch(stem,@"^(CON|PRN|AUX|NUL|COM[0-9]|LPT[0-9])$")) throw new Exception("Некорректный путь к базе.");
        }
        for (string p = full; !String.IsNullOrEmpty(p); p = Path.GetDirectoryName(p)) {
            if ((File.Exists(p) || Directory.Exists(p)) && (File.GetAttributes(p) & FileAttributes.ReparsePoint) != 0) throw new Exception("Выберите обычный файл и папку без символических ссылок.");
        }
        return full;
    }
    static Dictionary<string,object> Envelope(string data) {
        if (Utf8.GetByteCount(data) > Limit) throw new Exception("База превышает 8 МБ.");
        Dictionary<string,object> v;
        try {
            v = Json.Deserialize<Dictionary<string,object>>(data);
            if (v == null || v.Count != 9 || Text(v,"format") != "chrome-app-totp-vault" || Convert.ToInt32(v["version"]) != 1 || Text(v,"kdf") != "PBKDF2-SHA256" || Convert.ToInt32(v["iterations"]) != 600000 || Convert.ToInt64(v["revision"]) < 1 || Convert.ToDouble(v["revision"]) != Convert.ToInt64(v["revision"]) || Convert.ToInt64(v["revision"]) > 9007199254740991L || Convert.FromBase64String(Text(v,"salt")).Length != 16 || Convert.FromBase64String(Text(v,"iv")).Length != 12 || Convert.FromBase64String(Text(v,"ciphertext")).Length < 16) throw new Exception();
            object passwordLength;
            if (!v.TryGetValue("passwordLength",out passwordLength)) throw new Exception();
            if (!(passwordLength is int || passwordLength is long || passwordLength is decimal || passwordLength is double)) throw new Exception();
            decimal length = Convert.ToDecimal(passwordLength);
            if (length != 4m && length != 6m && length != 12m) throw new Exception();
        } catch { throw new Exception("Файл не является зашифрованной базой CHROME-APP-TOTP. Он не изменён."); }
        return v;
    }
    static string Token(Dictionary<string,object> v) { return v == null ? null : Text(v,"salt")+":"+Text(v,"iv")+":"+Convert.ToInt64(v["revision"]).ToString(System.Globalization.CultureInfo.InvariantCulture); }
    static string ReadVault(string path) {
        if (!File.Exists(path)) { if (Directory.Exists(path)) throw new Exception("Вместо файла указана папка."); return null; }
        // Bound the allocation even if another program replaces/grows the file.
        using (var stream = new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.Read)) {
            if (stream.Length > Limit) throw new Exception("База превышает 8 МБ.");
            using (var memory = new MemoryStream()) {
                byte[] buffer = new byte[65536]; int n;
                while ((n = stream.Read(buffer,0,buffer.Length)) != 0) { if (memory.Length + n > Limit) throw new Exception("База превышает 8 МБ."); memory.Write(buffer,0,n); }
                string data = Utf8.GetString(memory.ToArray()); Envelope(data); return data;
            }
        }
    }
    static void WriteVault(string path, string data, string expected) {
        Envelope(data);
        string before = ReadVault(path);
        if (Token(before == null ? null : Envelope(before)) != expected) throw new Exception("Файл изменился. Откройте базу заново; существующие данные не перезаписаны.");
        string dir = Path.GetDirectoryName(path); Directory.CreateDirectory(dir);
        string temp = Path.Combine(dir,".chrome-app-totp-"+Guid.NewGuid().ToString("N")+".tmp");
        try {
            var acl = new FileSecurity(); acl.SetAccessRuleProtection(true,false);
            acl.AddAccessRule(new FileSystemAccessRule(WindowsIdentity.GetCurrent().User,FileSystemRights.FullControl,AccessControlType.Allow));
            acl.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid,null),FileSystemRights.FullControl,AccessControlType.Allow));
            using (var stream = new FileStream(temp,FileMode.CreateNew,FileSystemRights.Write,FileShare.None,65536,FileOptions.WriteThrough,acl)) {
                byte[] bytes = Utf8.GetBytes(data); stream.Write(bytes,0,bytes.Length); stream.Flush(true);
            }
            // Recheck before atomic replacement; a new file uses a non-overwriting move.
            string current = ReadVault(path);
            if (Token(current == null ? null : Envelope(current)) != expected) throw new Exception("Файл изменился во время сохранения. Исходный файл не изменён.");
            if (before == null) File.Move(temp,path); else File.Replace(temp,path,null);
        } finally { if (File.Exists(temp)) File.Delete(temp); }
    }
    static void Run(Dictionary<string,object> request) {
        string op = Text(request,"op");
        if (op == "protect-key" || op == "unprotect-key") {
            byte[] source = null, result = null;
            try {
                string encoded = Text(request,op == "protect-key" ? "key" : "wrapped");
                if (request.Count != 2 || encoded == null || encoded.Length > (op == "protect-key" ? 44 : 5464)) throw new Exception();
                source = Convert.FromBase64String(encoded);
                if (Convert.ToBase64String(source) != encoded || (op == "protect-key" ? source.Length != 32 : source.Length < 32 || source.Length > 4096)) throw new Exception();
                if (op == "protect-key") {
                    result = ProtectedData.Protect(source,DeviceEntropy,DataProtectionScope.CurrentUser);
                    if (result.Length > 4096) throw new Exception();
                    Send(new { ok=true, wrapped=Convert.ToBase64String(result) });
                } else {
                    result = ProtectedData.Unprotect(source,DeviceEntropy,DataProtectionScope.CurrentUser);
                    if (result.Length != 32) throw new Exception();
                    Send(new { ok=true, key=Convert.ToBase64String(result) });
                }
            } catch { throw new Exception("Не удалось защитить или открыть ключ этого пользователя Windows. Введите пароль."); }
            finally { if (source != null) Array.Clear(source,0,source.Length); if (result != null) Array.Clear(result,0,result.Length); }
            return;
        }
        string path = ResolvePath(Text(request,"path"));
        if (op == "pick") {
            // This operation selects a path only; it never writes or truncates a file.
            System.Windows.Forms.Application.EnableVisualStyles();
            using (var dialog = new System.Windows.Forms.OpenFileDialog()) {
                dialog.AutoUpgradeEnabled = true;
                dialog.Title = "Выберите файл базы CHROME-APP-TOTP";
                dialog.Filter = "База TOTP (*.vault;*.json)|*.vault;*.json";
                dialog.DefaultExt = "vault"; dialog.AddExtension = true;
                dialog.CheckFileExists = false; dialog.CheckPathExists = true;
                dialog.Multiselect = false; dialog.RestoreDirectory = true;
                dialog.FileName = Path.GetFileName(path);
                if (Directory.Exists(Path.GetDirectoryName(path))) dialog.InitialDirectory = Path.GetDirectoryName(path);
                if (dialog.ShowDialog() != System.Windows.Forms.DialogResult.OK) { Send(new { ok=true, cancelled=true }); return; }
                Send(new { ok=true, path=ResolvePath(dialog.FileName) }); return;
            }
        }
        string mutexName;
        using (var hash = SHA256.Create()) mutexName = "Local\\ChromeAppTotp-"+BitConverter.ToString(hash.ComputeHash(Utf8.GetBytes(path.ToUpperInvariant()))).Replace("-","");
        using (var mutex = new Mutex(false,mutexName)) {
            bool held = false;
            try {
                try { held = mutex.WaitOne(5000); } catch (AbandonedMutexException) { held = true; }
                if (!held) throw new Exception("Файл занят другим окном. Повторите сохранение.");
                if (op == "status") { Send(new { ok=true, path=path, defaultPath=DefaultPath(), exists=File.Exists(path) }); return; }
                if (op == "read") {
                    string data = ReadVault(path);
                    if (data != null) for (int i=0; i<data.Length; i+=200000) Send(new { chunk=data.Substring(i,Math.Min(200000,data.Length-i)) });
                    Send(new { ok=true, path=path, exists=data!=null }); return;
                }
                if (op == "write") { WriteVault(path,Text(request,"data") ?? "",Text(request,"expectedToken")); Send(new { ok=true, path=path }); return; }
                throw new Exception("Неизвестная операция.");
            } finally { if (held) mutex.ReleaseMutex(); }
        }
    }
    [STAThread] static void Main(string[] args) {
        if (args.Length == 0 || args[0] != Origin) return;
        input = Console.OpenStandardInput(); output = Console.OpenStandardOutput();
        // One bounded operation; a dead caller never leaves a resident helper.
        using (var watchdog = new Timer(delegate { Environment.Exit(1); },null,30000,Timeout.Infinite)) {
            try { int length = BitConverter.ToInt32(ReadExact(4),0); if (length < 2 || length > 17000000) throw new Exception("Некорректный запрос."); var request = Json.Deserialize<Dictionary<string,object>>(Utf8.GetString(ReadExact(length))); if (Text(request,"op") == "pick") watchdog.Change(300000,Timeout.Infinite); Run(request); }
            catch (Exception e) { try { Send(new { ok=false, error=e is UnauthorizedAccessException ? "Нет доступа к файлу базы. Выберите доступную папку в настройках." : e.Message }); } catch {} }
        }
    }
}
