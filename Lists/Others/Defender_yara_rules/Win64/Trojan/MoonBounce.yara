rule Trojan_Win64_MoonBounce_A_2147811487_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/MoonBounce.A"
        threat_id = "2147811487"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "MoonBounce"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 63 58 3c be 00 20 00 00 45 8b cc 48 03 d8 44 8b c6 8b 53 50 48 8b 4b 30 41 ff 56 10}  //weight: 1, accuracy: High
        $x_1_2 = {8b 53 50 45 8b cc 44 8b c6 33 c9 41 ff 56 10}  //weight: 1, accuracy: High
        $x_1_3 = {b8 89 88 88 88 f7 e9 03 d1 c1 fa 03 8b c2 c1 e8 1f 03 d0 42 8d 04 82 8b c8 c1 e8 03}  //weight: 1, accuracy: High
        $x_1_4 = {48 8d 83 e0 01 00 00 4c 8d 8b c0 01 00 00 48 89 ?? ?? ?? 4c 8d 83 80 01 00 00 48 8d 93 1c 01 00 00 48 8b cb 48 89 ?? ?? ?? e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win64_MoonBounce_B_2147811489_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/MoonBounce.B!!MoonBounce.B"
        threat_id = "2147811489"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "MoonBounce"
        severity = "Critical"
        info = "MoonBounce: an internal category used to refer to some threats"
        info = "B: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 63 58 3c be 00 20 00 00 45 8b cc 48 03 d8 44 8b c6 8b 53 50 48 8b 4b 30 41 ff 56 10}  //weight: 1, accuracy: High
        $x_1_2 = {8b 53 50 45 8b cc 44 8b c6 33 c9 41 ff 56 10}  //weight: 1, accuracy: High
        $x_1_3 = {b8 89 88 88 88 f7 e9 03 d1 c1 fa 03 8b c2 c1 e8 1f 03 d0 42 8d 04 82 8b c8 c1 e8 03}  //weight: 1, accuracy: High
        $x_1_4 = {48 8d 83 e0 01 00 00 4c 8d 8b c0 01 00 00 48 89 ?? ?? ?? 4c 8d 83 80 01 00 00 48 8d 93 1c 01 00 00 48 8b cb 48 89 ?? ?? ?? e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

