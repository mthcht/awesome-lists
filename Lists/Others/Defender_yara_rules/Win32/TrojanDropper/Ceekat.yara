rule TrojanDropper_Win32_Ceekat_B_2147626698_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Ceekat.B"
        threat_id = "2147626698"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Ceekat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a fc 53 e8 ?? ?? ff ff 6a 00 8d 44 24 04 50 6a 04 8d 44 24 10 50 53 e8 ?? ?? ff ff 81 74 24 04 ?? ?? ?? ?? 6a 00}  //weight: 1, accuracy: Low
        $x_1_2 = {7e 19 8a 83 ?? ?? ?? ?? 30 06 46 43 8b c3 bb 07 00 00 00 99 f7 fb 8b da 49 75 e7}  //weight: 1, accuracy: Low
        $x_1_3 = {c6 00 55 b8 ?? ?? ?? ?? e8 ?? ?? ff ff c6 40 01 44}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

