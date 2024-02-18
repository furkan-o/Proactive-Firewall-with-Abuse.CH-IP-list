using System;
using System.IO;
using System.Net;
using System.Diagnostics;
using System.Text.RegularExpressions;

class Program
{
    static void Main()
    {
        // Download File
        string url = "https://urlhaus.abuse.ch/downloads/text_online/";
        string response;
        using (WebClient client = new WebClient())
        {
            response = client.DownloadString(url);
        }

        // Remove the existing firewall rule if it exists
        string rule = "AbuseCH_IPs";
        if (FirewallRuleExists(rule))
        {
            DeleteFirewallRule(rule);
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
            if (parts.Length >= 2 && IsValidIpAddress(parts[1]))
            {
                ipAddresses.Add(parts[1]);
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
        string ruleName = $"AbuseCH_IPs";
        string rule = $"netsh advfirewall firewall add rule name=\"{ruleName}\" dir=out action=block remoteip={ip}";

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
        string rule = $"netsh advfirewall firewall delete rule name='{ruleName}'";

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
            process.StartInfo.Arguments = $"advfirewall firewall show rule name={ruleName}";
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
}
