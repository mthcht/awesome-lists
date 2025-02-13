rule TrojanClicker_Win32_Erbon_A_2147691001_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/Erbon.A"
        threat_id = "2147691001"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "Erbon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\*.txt" wide //weight: 1
        $x_1_2 = "&time=" wide //weight: 1
        $x_2_3 = "\\servicesc.exe " wide //weight: 2
        $x_3_4 = "http://c.l7l73.net.cn/test/err.asp?alerr=sub:timer3__errnb:" wide //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

