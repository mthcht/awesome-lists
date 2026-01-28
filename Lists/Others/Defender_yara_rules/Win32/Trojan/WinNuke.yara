rule Trojan_Win32_WinNuke_AMTB_2147961825_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/WinNuke!AMTB"
        threat_id = "2147961825"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "WinNuke"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WinNuke 98 Attacking" ascii //weight: 1
        $x_1_2 = "WinNuke! Win'98 / Don't Touch its !" ascii //weight: 1
        $x_1_3 = "Nuke Attack" ascii //weight: 1
        $x_1_4 = "WinNuke 98 Attacking.vbp" ascii //weight: 1
        $x_1_5 = "http://www.hackerworld.com/nuke.html" ascii //weight: 1
        $x_1_6 = "WinNuke Attacking Port Successfully" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

