rule TrojanClicker_Win32_Ilafor_A_2147612629_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/Ilafor.A"
        threat_id = "2147612629"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "Ilafor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 fb 02 75 06 c6 45 ?? 70 eb 04 c6 45 ?? 71}  //weight: 1, accuracy: Low
        $x_1_2 = {fe cb 74 1d fe cb 0f 84 ?? ?? 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {2a 71 3d 2a 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

