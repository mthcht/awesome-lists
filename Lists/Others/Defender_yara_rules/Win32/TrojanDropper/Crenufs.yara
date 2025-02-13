rule TrojanDropper_Win32_Crenufs_A_2147644030_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Crenufs.A"
        threat_id = "2147644030"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Crenufs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 83 c9 fc 41 8a 54 14 14 8a 5c 0c 10 32 d3 8a 98 ?? ?? ?? ?? 32 da 88 98 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 40 3b c1 72 bf}  //weight: 1, accuracy: Low
        $x_1_2 = {ff d7 8b c8 bb 03 00 00 00 99 f7 fb 85 d2 75 0f 8b c1 b9 19 00 00 00 99 f7 f9 80 c2 61 eb 1e}  //weight: 1, accuracy: High
        $x_1_3 = {3a 66 75 6e 63 73 69 7a 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

