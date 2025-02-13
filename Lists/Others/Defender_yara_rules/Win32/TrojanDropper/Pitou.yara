rule TrojanDropper_Win32_Pitou_B_2147688349_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Pitou.B"
        threat_id = "2147688349"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Pitou"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 7c 7a bd e4 e8 ?? ?? ?? ?? 8b 00 ff d0}  //weight: 1, accuracy: Low
        $x_1_2 = {33 d1 8b 45 0c 88 10 8b 4d 0c 83 c1 01 89 4d 0c 8b 55 f4 83 c2 01 89 55 f4 8b 45 f8 03 45 f0 0f b6 08 d1 e1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

