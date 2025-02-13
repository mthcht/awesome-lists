rule Trojan_Win32_Toga_2147696168_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Toga!rfn"
        threat_id = "2147696168"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Toga"
        severity = "Critical"
        info = "rfn: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 45 f0 8b 45 fc 8b 40 28 03 45 f4 8b 55 f0 89 42 04 8b 45 f0 8b 55 f4 89 10 8b 45 fc 05 a0 00 00 00 8b 10 85 d2 74 0c}  //weight: 1, accuracy: High
        $x_1_2 = {8b 45 fc 83 c0 78 8b 10 85 d2 74 18 03 55 f4 8b 4d f0 89 91 ?? ?? ?? ?? 8b 40 04 8b 55 f0 89 82 ?? ?? ?? ?? 8b 45 fc}  //weight: 1, accuracy: Low
        $x_1_3 = {6a 00 6a 01 8b 45 f4 50 8b 45 f0 ff 50 04 85 c0 75 0a 8b 45 f0 33 d2 89 50 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Toga_2147696168_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Toga!rfn"
        threat_id = "2147696168"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Toga"
        severity = "Critical"
        info = "rfn: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f bf d0 8b 85 b0 fe ff ff 8d 8d 54 ff ff ff 33 c2 50 51 ff 15 ?? ?? ?? ?? 8d 95 c4 fe ff ff 8d 85 54 ff ff ff 52 8d 8d 44 ff ff ff}  //weight: 1, accuracy: Low
        $x_1_2 = {8b c8 8b c6 99 f7 f9 c7 45 c4 03 00 00 00 89 55 cc 8b 55 e0 52 ff d7 8b c8 8b c6 99 f7 f9 8d 45 c4 8d 8d 34 ff ff ff}  //weight: 1, accuracy: High
        $x_1_3 = {8b 55 e0 89 45 bc 52 c7 45 b4 03 00 00 00 ff d7 8b c8 8b c6 99 f7 f9 c7 45 c4 03 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

