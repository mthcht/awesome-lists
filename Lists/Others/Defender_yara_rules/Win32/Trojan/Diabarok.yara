rule Trojan_Win32_Diabarok_A_2147636862_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Diabarok.A"
        threat_id = "2147636862"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Diabarok"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 55 f8 8a 02 8b ce c1 e9 08 32 c8 88 0a 25 ff 00 00 00 03 f0 69 c6 6d ce 00 00 05 bf 58 00 00 8b f0 ff 45 f8 4b 85 db 75 d6}  //weight: 1, accuracy: High
        $x_1_2 = {c6 02 e9 8b 0c 24 2b c8 2b cb 83 e9 05 42 89 0a}  //weight: 1, accuracy: High
        $x_1_3 = {8d 45 f8 b2 3a e8 ?? ?? ?? ?? 8b 55 e0 8b 45 ec 8b 00 c1 e0 05 8b 4d ec 8d 44 c1 04 e8 ?? ?? ?? ?? 8d 4d dc 8d 45 f8 b2 7c}  //weight: 1, accuracy: Low
        $x_1_4 = {74 1b 8b c3 c1 e0 05 8d 84 c7 04 00 01 00 50 e8 1b e6 ff ff 8b 55 f8 89 02 b3 01 eb 06}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

