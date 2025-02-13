rule Trojan_Win32_Lephweb_A_2147626879_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lephweb.A"
        threat_id = "2147626879"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lephweb"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Explorer.exe webhelp.exe" ascii //weight: 1
        $x_1_2 = {77 65 62 73 68 6f 77 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_3 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" ascii //weight: 1
        $x_1_4 = ":\\test.txt.pop" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

