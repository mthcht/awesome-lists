rule TrojanClicker_Win32_Haglacod_A_2147687577_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/Haglacod.A"
        threat_id = "2147687577"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "Haglacod"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3f 61 3d 53 65 61 72 63 68 26 71 3d 00}  //weight: 1, accuracy: High
        $x_1_2 = "/Flash" ascii //weight: 1
        $x_1_3 = "/info.txt" ascii //weight: 1
        $x_1_4 = {ba 27 02 00 00 8b 86 f8 02 00 00 e8 ?? ?? ?? ?? 8d 55 fc b8 1a 00 00 00 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

