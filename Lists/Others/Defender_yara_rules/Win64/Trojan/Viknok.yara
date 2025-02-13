rule Trojan_Win64_Viknok_A_2147680234_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Viknok.A"
        threat_id = "2147680234"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Viknok"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {65 48 8b 04 25 30 00 00 00 41 0f b7 e9 8b fa 4c 8b 50 60 33 c0 48 8b d9 49 8b 72 18}  //weight: 1, accuracy: High
        $x_1_2 = {eb 11 81 fb ?? ?? 00 00 73 18 b9 64 00 00 00 ff d6 ff c3 e8 ?? ?? ?? ?? 48 8b c8 ff d7 41 3b c7 74 e0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

