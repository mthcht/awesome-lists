rule Trojan_Win32_Fsvc_A_2147603340_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fsvc.A"
        threat_id = "2147603340"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fsvc"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 1
        $x_1_2 = "sql2005.dll" ascii //weight: 1
        $x_1_3 = "notepad.exe" ascii //weight: 1
        $x_1_4 = "Key Folder\\svschosts.exe " ascii //weight: 1
        $x_1_5 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_6 = "SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile\\EnableFirewall" ascii //weight: 1
        $x_1_7 = "CreateDirectoryA" ascii //weight: 1
        $x_1_8 = "GetClipboardData" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

