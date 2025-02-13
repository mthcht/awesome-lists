rule Trojan_Win32_Ordpea_A_2147599278_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ordpea.A"
        threat_id = "2147599278"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ordpea"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f 85 d2 00 00 00 b8 ?? ?? ?? ?? e8 ?? ?? ff ff 85 c0 75 31 8d 45 d8 11 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? e8 ?? ?? ff ff 85 c0}  //weight: 1, accuracy: Low
        $x_1_2 = {f4 ff ff 68 ?? ?? 40 00 68 ?? ?? 40 00 e8 ?? ?? ff ff 85 c0 0f 85 ?? (02|03) 00 00 83 3d ?? ?? 40 00 00 0f 85 ?? 02 00 00 8d 55 19 00 e8}  //weight: 1, accuracy: Low
        $x_3_3 = {76 33 66 bf 01 00 0f b7 c7 8b 55 fc 0f b6 44 02 ff 66 89 45 fa 8d 45 f4 66 8b 55 fa 66 83 f2 ?? e8 ?? ?? ff ff 8b 55 f4 8b c6 e8 ?? ?? ff ff 47 66 ff cb 75 d1}  //weight: 3, accuracy: Low
        $x_1_4 = {8d 45 d0 ba 04 00 00 00 e8 ?? ?? ?? ?? 8b 55 d0 8b 45 f0 e8 ?? ?? ?? ?? 8d 55 cc 8b 45 f0 e8 ?? ?? ?? ?? 68 ?? ?? ?? ?? ff 75 10 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8d 45 c8 ba 04 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_3_*))) or
            (all of ($x*))
        )
}

