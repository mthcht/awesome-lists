rule Trojan_Win32_Sauratol_A_2147575173_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sauratol.A"
        threat_id = "2147575173"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sauratol"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/c del \"C:\\myapp.exe" ascii //weight: 1
        $x_1_2 = "<IFRAME SRC=\"HTTP://www." ascii //weight: 1
        $x_1_3 = "htm-html-asp-aspx-php" ascii //weight: 1
        $x_1_4 = "www.ysbr.cn" ascii //weight: 1
        $x_1_5 = "WIDTH=0 HEIGHT=0></IFRAME>" ascii //weight: 1
        $x_1_6 = "svchost.exe" ascii //weight: 1
        $x_1_7 = "C:\\WINDOWS\\SYSTE\\x20\\x00" ascii //weight: 1
        $x_1_8 = "C:\\WINDOWS\\SYSTEM32" ascii //weight: 1
        $x_1_9 = "Remote Help Session Manager" ascii //weight: 1
        $x_1_10 = "Rasautol" ascii //weight: 1
        $x_1_11 = "/c del \"C:\\/c" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (9 of ($x*))
}

