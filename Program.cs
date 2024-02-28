using System;
using System.Diagnostics;
using System.Net;
using System.Security.Principal;
using System.Text.RegularExpressions;

class Program
{
    static void Main()
    {
        // Check if running as administrator
        if (!IsAdministrator())
        {
            // Restart program and request elevation
            RestartAsAdministrator();
            return;
        }

        // Download File
        string url = "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt";
        string response;
        using (WebClient client = new WebClient())
        {
            response = client.DownloadString(url);
        }

        // Remove the existing firewall rule if it exists
        if (FirewallRuleExists("AbuseCH_IPs"))
        {
            DeleteFirewallRule("AbuseCH_IPs");
        }

        // Extract IP addresses
        string[] ipAddresses = ExtractIpAddresses(response);

        // Block the extracted IP addresses
        foreach (string ip in ipAddresses)
        {
            string blockedIp = BlockIpAddress(ip);
            Console.WriteLine($"{blockedIp} added to the Firewall.");
        }
    }

    static string[] ExtractIpAddresses(string response)
    {
        var ipAddresses = new System.Collections.Generic.List<string>();

        // Remove comments and split lines
        string[] lines = response.Split(new[] { "\r\n", "\r", "\n" }, StringSplitOptions.RemoveEmptyEntries);
        foreach (string line in lines)
        {
            string[] parts = line.Split(',');
            if (parts.Length >= 1 && IsValidIpAddress(parts[0]))
            {
                ipAddresses.Add(parts[0]);
            }
        }

        return ipAddresses.ToArray();
    }

    static bool IsValidIpAddress(string input)
    {
        Regex regex = new Regex(@"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$");
        return regex.IsMatch(input);
    }

    static string BlockIpAddress(string ip)
    {
        string rule = $"netsh advfirewall firewall add rule name=AbuseCH_IPs dir=out action=block remoteip={ip}";

        using (Process process = new Process())
        {
            process.StartInfo.FileName = "powershell.exe";
            process.StartInfo.Arguments = $"-Command \"{rule}\"";
            process.StartInfo.RedirectStandardOutput = true;
            process.StartInfo.RedirectStandardError = true;
            process.StartInfo.UseShellExecute = false;
            process.StartInfo.CreateNoWindow = true;

            process.Start();
            process.WaitForExit();
        }

        return ip;
    }

    static void DeleteFirewallRule(string ruleName)
    {
        string rule = $"netsh advfirewall firewall delete rule name=AbuseCH_IPs";

        using (Process process = new Process())
        {
            process.StartInfo.FileName = "powershell.exe";
            process.StartInfo.Arguments = $"-Command \"{rule}\"";
            process.StartInfo.RedirectStandardOutput = true;
            process.StartInfo.RedirectStandardError = true;
            process.StartInfo.UseShellExecute = false;
            process.StartInfo.CreateNoWindow = true;

            process.Start();
            process.WaitForExit();
        }
    }

    static bool FirewallRuleExists(string ruleName)
    {
        using (Process process = new Process())
        {
            process.StartInfo.FileName = "netsh";
            process.StartInfo.Arguments = $"advfirewall firewall show rule name=AbuseCH_IPs";
            process.StartInfo.RedirectStandardOutput = true;
            process.StartInfo.RedirectStandardError = true;
            process.StartInfo.UseShellExecute = false;
            process.StartInfo.CreateNoWindow = true;

            process.Start();
            string output = process.StandardOutput.ReadToEnd();
            process.WaitForExit();

            return !output.Contains("No rules match the specified criteria");
        }
    }

    static bool IsAdministrator()
    {
        WindowsIdentity identity = WindowsIdentity.GetCurrent();
        WindowsPrincipal principal = new WindowsPrincipal(identity);
        return principal.IsInRole(WindowsBuiltInRole.Administrator);
    }

    static void RestartAsAdministrator()
    {
        ProcessStartInfo startInfo = new ProcessStartInfo
        {
            FileName = System.Reflection.Assembly.GetExecutingAssembly().CodeBase,
            UseShellExecute = true,
            Verb = "runas" // Run as administrator
        };
        Process.Start(startInfo);
    }
}
