rule TrojanDropper_Win32_Ropest_A_2147688397_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Ropest.A"
        threat_id = "2147688397"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Ropest"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 e8 0d 0f 84 ?? ?? ?? ?? 48 74 3f 2d 03 01 00 00 75 24}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 48 3c 8b 4c 01 58 50 89 0d ?? ?? ?? ?? c6 45 ff 01}  //weight: 1, accuracy: Low
        $x_1_3 = {3d e4 85 43 31 0f 84 ?? ?? ?? ?? 3d f7 dc ee b1 0f 84}  //weight: 1, accuracy: Low
        $x_1_4 = {83 fe 04 72 02 33 f6 8a 14 01 32 96 ?? ?? ?? ?? 88 10 40 46 4f 75 e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

