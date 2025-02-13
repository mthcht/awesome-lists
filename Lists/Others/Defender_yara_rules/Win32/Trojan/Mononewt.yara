rule Trojan_Win32_Mononewt_A_2147814867_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Mononewt.A!dha"
        threat_id = "2147814867"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Mononewt"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "lpszVerb:%s" wide //weight: 1
        $x_1_2 = "/search?hl=en&q=%s&meta=%s" ascii //weight: 1
        $x_1_3 = "Software\\Microsoft\\Keyboard\\Set" wide //weight: 1
        $x_1_4 = "%s\\cnf_%s_%s.txt" wide //weight: 1
        $x_1_5 = "\\Microsoft\\Media Player" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

