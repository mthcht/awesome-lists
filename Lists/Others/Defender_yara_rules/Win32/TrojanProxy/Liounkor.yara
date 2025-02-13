rule TrojanProxy_Win32_Liounkor_A_2147679847_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Liounkor.A"
        threat_id = "2147679847"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Liounkor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c4 04 81 3d ?? ?? ?? ?? 38 04 00 00 7c 0c 81 3d ?? ?? ?? ?? ff ff 00 00 7e 0d ff 15 ?? ?? ?? ?? a3 ?? ?? ?? ?? eb db}  //weight: 1, accuracy: Low
        $x_1_2 = {99 b9 05 00 00 00 f7 f9 89 55 fc ba 01 00 00 00 85 d2 74 76 eb 09 8b 45 fc 83 c0 01 89 45 fc 83 7d fc 05 7d 42}  //weight: 1, accuracy: High
        $x_1_3 = {68 b8 22 00 00 e8 ?? ?? ?? ?? 66 89 85 06 ed ff ff 8a 0d ?? ?? ?? ?? 88 8d 00 ff ff ff b9 3f 00 00 00 33 c0 8d bd 01 ff ff ff f3 ab 66 ab aa}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

