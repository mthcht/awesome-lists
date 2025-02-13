rule TrojanClicker_Win32_Hidprop_A_2147706433_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/Hidprop.A"
        threat_id = "2147706433"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "Hidprop"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "hider\\Project1.vbp" wide //weight: 1
        $x_1_2 = "youtube/index.php?act=console&phone=" wide //weight: 1
        $x_1_3 = "37.59.246.141" wide //weight: 1
        $x_1_4 = "tskill iexplore" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

