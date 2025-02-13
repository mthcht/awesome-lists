rule TrojanClicker_Win32_Vbadult_A_2147625465_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/Vbadult.A"
        threat_id = "2147625465"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "Vbadult"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Project1.vbp" wide //weight: 1
        $x_1_2 = {0a 00 00 00 24 00 69 00 6d 00 67 00 24 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "PayTime :" wide //weight: 1
        $x_1_4 = "\\Macromedia\\Flash Player\\#SharedObjects\\" wide //weight: 1
        $x_1_5 = "software\\microsoft\\windows\\currentversion\\run" wide //weight: 1
        $x_1_6 = "WScript.Shell" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

