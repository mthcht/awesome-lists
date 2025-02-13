rule Trojan_Win32_Witkinat_A_2147630727_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Witkinat.A"
        threat_id = "2147630727"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Witkinat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 77 75 70 64 2e 64 61 74 [0-5] 5c 77 65 78 65 2e 65 78 65 [0-5] 5c 77 6f 72 6b 2e 64 61 74}  //weight: 1, accuracy: Low
        $x_1_2 = {83 c2 05 8b c3 e8 ?? ?? ?? ?? 8b d6 83 c2 04 88 02 c6 03 e9 47 8b 45 f4 89 07}  //weight: 1, accuracy: Low
        $x_1_3 = {eb 1c 80 7c 24 08 09 75 03 47 eb 12 8d 44 24 18 50 e8 ?? ?? ?? ?? 8a 54 24 08 88 54 04 18 43 3b 1c 24 0f 82}  //weight: 1, accuracy: Low
        $x_1_4 = {80 fb 44 75 11 68 b4 b2 40 00 8d 85 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 80 fb 55 75 11 68 ?? ?? ?? ?? 8d 85 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 80 fb 55 74 05 80 fb 44 75 6b}  //weight: 1, accuracy: Low
        $x_2_5 = {8d 04 0f 33 d2 f7 f5 8a 82 ?? ?? ?? ?? 8a 13 32 c2 88 03 47 43 4e 75 e8}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

