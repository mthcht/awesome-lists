rule PWS_Win64_Hesperbot_A_2147690345_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win64/Hesperbot.A"
        threat_id = "2147690345"
        type = "PWS"
        platform = "Win64: Windows 64-bit platform"
        family = "Hesperbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 bb 3b a7 ca 84 85 ae 67 bb 49 bf 08 c9 bc f3 67 e6 09 6a 48 bf 2b f8 94 fe 72 f3 6e 3c}  //weight: 1, accuracy: High
        $x_1_2 = {48 b9 f1 36 1d 5f 3a f5 4f a5 49 8b c6 48 89 4c 24 48 48 b9 d1 82 e6 ad 7f 52 0e 51 48 89 5c 24 38}  //weight: 1, accuracy: High
        $x_1_3 = {4c 2b c0 8b d6 48 8d 4c 14 39 48 ff c2 41 0f b6 04 08 88 01 48 83 fa 04 72 eb}  //weight: 1, accuracy: High
        $x_2_4 = {68 76 6e 63 5f 6d 6f 64 5f 78 36 34 2e 6d 6f 64 00 6d 6f 64 5f 65 6e 74 72 79}  //weight: 2, accuracy: High
        $x_1_5 = {bf 1b b9 2f 91 4c 8d 05 ?? ?? ?? ?? 8b d3 8b cf 66 39 15 ?? ?? ?? ?? 74 0a 48 ff c2 66 41 39 1c 50 75 f6}  //weight: 1, accuracy: Low
        $x_1_6 = {b9 54 12 12 95 4c 8b cb 48 c7 44 24 20 10 00 00 00 41 ff 52 38 48 8b c3 48 83 c4 30 5b c3}  //weight: 1, accuracy: High
        $x_1_7 = {0f 84 51 01 00 00 41 0f b7 c0 bf 01 00 00 00 83 c0 9c 83 f8 12 0f 87 3a 01 00 00 4c 8d 05 91 a1 ff ff}  //weight: 1, accuracy: High
        $x_1_8 = {49 8b c3 49 f7 e0 49 8b c0 49 ff c0 48 c1 ea 05 48 6b d2 36 48 2b c2 0f b6 04 38 41 32 04 0a 88 01 4d 3b c1 72 d5}  //weight: 1, accuracy: High
        $x_1_9 = {49 8b c0 48 c1 f8 05 83 e1 1f 49 8b 04 c2 48 6b c9 58 4c 8b 14 01 49 83 fa ff 74 0b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

