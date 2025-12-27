rule Trojan_Win32_NebulaWorm_AHB_2147947689_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NebulaWorm.AHB!MTB"
        threat_id = "2147947689"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NebulaWorm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {06 02 03 6f b8 00 00 0a 04 6f b9 00 00 0a 2c 08 06 6f ba 00 00 0a 2b 01 16 0b de 0f}  //weight: 3, accuracy: High
        $x_2_2 = {0a 18 33 56 09 6f ?? 00 00 0a 6f ?? 00 00 0a 13 04 11 04 72 be 15 00 70 28 2b 00 00 0a 13 05 11 05 28 24 00 00 0a 2d 10 06 11 05 28 c3 00 00 0a 11 05 1c 28 c4 00 00 0a 11 04 72 da 15 00 70 28 2b 00 00 0a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

