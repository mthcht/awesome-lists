rule Trojan_Win32_Ruandmel_A_2147711329_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ruandmel.A!bit"
        threat_id = "2147711329"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ruandmel"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 04 8d 04 40 8b 0c 85 ?? ?? ?? ?? 8b 44 24 08 8b 44 c1 04 8b 0c 24 83 c4 08 89 0c 24 ff e0}  //weight: 1, accuracy: Low
        $x_1_2 = {2b c7 89 45 0c 8a 04 38 88 45 13 8b 01 40 25 ff 00 00 00 8d 34 01 89 01 0f b6 46 08 03 41 04 25 ff 00 00 00 89 41 04 8a 56 08 0f b6 44 08 08 88 46 08 8b 41 04 88 54 08 08 85 ff 74 ?? 8b 41 04 0f b6 54 08 08 8b 01 0f b6 44 08 08 03 d0 81 e2 ff 00 00 80 79 ?? 4a 81 ca 00 ff ff ff 42 8a 54 0a 08 32 55 13 88 17 8b 45 0c 47 4b 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

