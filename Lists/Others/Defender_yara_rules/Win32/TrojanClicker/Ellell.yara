rule TrojanClicker_Win32_Ellell_A_2147690637_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/Ellell.A"
        threat_id = "2147690637"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "Ellell"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "http://no2oplove.com/llll.html?search=" ascii //weight: 2
        $x_1_2 = {80 b1 00 30 40 00 5c 41 8b d9 3b d8 74 02 eb f0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

