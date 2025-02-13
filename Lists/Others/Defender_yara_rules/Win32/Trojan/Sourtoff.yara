rule Trojan_Win32_Sourtoff_A_2147685619_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sourtoff.A"
        threat_id = "2147685619"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sourtoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "33"
        strings_accuracy = "Low"
    strings:
        $x_16_1 = {6a 0c 59 33 ff 33 c0 66 ad 3c 61 7c 02 2c 20 c1 cf 0d 03 f8 e2 ef 81 ff 17 ca 2b 6e}  //weight: 16, accuracy: High
        $x_16_2 = {6a 43 ff 15 ?? ?? ?? ?? 85 c0 74 ?? e8 ?? ?? ?? ?? 04 0d 0c 0c 0d 8b 35 ?? ?? ?? ?? bf 00 00 03 00 57 6a 06 8b 35 ?? ?? ?? ?? 68 00 00 03 00 6a 06 68 00 00 03 00 6a 06 8b 35 ?? ?? ?? ?? bb 00 00 03 00 53 6a 06 8b 35 ?? ?? ?? ?? ff d6 85 c0 75 ?? 03 05 01 01 68 00 00 03 00 57 53 6a 04 ff d6}  //weight: 16, accuracy: Low
        $x_1_3 = {33 d2 8b c6 f7 35 ?? ?? ?? ?? a1 ?? ?? ?? ?? c7 45 fc ff 00 00 00 8a 0c 02 33 d2 32 0c 1e 8b c6 f7 75 fc 32 0d ?? ?? ?? ?? fe c1 02 ca 88 0c 1e 46 4f 75 cc}  //weight: 1, accuracy: Low
        $x_1_4 = {33 d2 8b c6 f7 35 ?? ?? ?? ?? 8b c6 c7 44 24 10 ff 00 00 00 8a 0c 2a 33 d2 f7 74 24 10 32 0c 1e 32 0d ?? ?? ?? ?? fe c1 02 ca 88 0c 1e 46 4f 75 cf}  //weight: 1, accuracy: Low
        $x_1_5 = {4d 69 6e 69 44 75 6d 70 57 72 69 74 65 44 75 6d 70 00 00 00 20 32 30 30 20 00 00 00 20 34 34 34 20 00 00 00 20 34 34 35 20 00 00 00 20 34 34 36 20 00 00 00 20 34 34 37 20}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_16_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

