rule TrojanClicker_Win32_Popal_A_2147689623_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/Popal.A"
        threat_id = "2147689623"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "Popal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 3d e0 60 40 00 8b ff 68 ?? ?? ?? ?? ff d6 6a 01 6a 00 6a 00 68 ?? ?? ?? ?? 68 60 78 40 00 6a 00 ff d7 68 ?? ?? ?? ?? ff d6}  //weight: 10, accuracy: Low
        $x_1_2 = "ads.babal.net" ascii //weight: 1
        $x_1_3 = "\\POP\\Release\\pop" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

