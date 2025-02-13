rule Backdoor_Win32_Robofo_A_2147619538_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Robofo.A"
        threat_id = "2147619538"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Robofo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "710"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 100
        $x_100_2 = "\\config\\SteamAppData.vdf" ascii //weight: 100
        $x_100_3 = "203.121.79.49" ascii //weight: 100
        $x_100_4 = "54321" ascii //weight: 100
        $x_100_5 = "RoboForm" ascii //weight: 100
        $x_100_6 = "System32\\drivers\\ssl" ascii //weight: 100
        $x_100_7 = "SYSTEM\\CurrentControlSet\\Control\\Lsa\\disabledomaincreds" ascii //weight: 100
        $x_2_8 = "\\Mozilla\\FireFox\\" ascii //weight: 2
        $x_2_9 = "\\Opera\\" ascii //weight: 2
        $x_2_10 = "www2.scasd.org" ascii //weight: 2
        $x_2_11 = "in-2-web2.com" ascii //weight: 2
        $x_2_12 = "www.huquqalinsan.com" ascii //weight: 2
        $x_2_13 = "SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile\\EnableFirewall" ascii //weight: 2
        $x_1_14 = "http://www.google.com" ascii //weight: 1
        $x_1_15 = "hotmail" ascii //weight: 1
        $x_1_16 = "Logs/Pass" ascii //weight: 1
        $x_1_17 = "*delfile*" ascii //weight: 1
        $x_1_18 = "*execute*" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_100_*) and 3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((7 of ($x_100_*) and 4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((7 of ($x_100_*) and 5 of ($x_2_*))) or
            (all of ($x*))
        )
}

