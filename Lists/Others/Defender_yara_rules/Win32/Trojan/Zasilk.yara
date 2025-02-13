rule Trojan_Win32_Zasilk_A_2147625876_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zasilk.A"
        threat_id = "2147625876"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zasilk"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ShowSuperHidden" wide //weight: 1
        $x_1_2 = "MRHELL" wide //weight: 1
        $x_1_3 = "\\Folder.htt" wide //weight: 1
        $x_1_4 = "System Monitoring" wide //weight: 1
        $x_1_5 = "lnkfile\\shell\\open\\command" wide //weight: 1
        $x_1_6 = "NT\\CurrentVersion\\AeDebug" wide //weight: 1
        $x_1_7 = "0100 4D 5A 36 01 01 00" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

