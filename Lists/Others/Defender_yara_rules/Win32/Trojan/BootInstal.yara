rule Trojan_Win32_BootInstal_A_2147641863_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BootInstal.A!dll"
        threat_id = "2147641863"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BootInstal"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {62 6f 6f 74 69 6e 73 74 61 6c 6c 2e 64 6c 6c 00 62 6f 6f 74 70 72 6f}  //weight: 3, accuracy: High
        $x_1_2 = "Connection Wizard\\iexplore.exe" ascii //weight: 1
        $x_1_3 = "CLSID\\{1f4de370-d627-11d1-ba4f-00a0c91eedba}" ascii //weight: 1
        $x_1_4 = "Rundll32.exe Shell32.dll,Control_RunDLL Inetcpl.cpl" ascii //weight: 1
        $x_1_5 = "\\360se\\data\\bookmarks.dat" ascii //weight: 1
        $x_1_6 = "\\CurrentVersion\\Winlogon\\Notify\\Cevennet\\" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

