rule Trojan_Win64_Hadsyima_A_2147910375_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Hadsyima.A"
        threat_id = "2147910375"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Hadsyima"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {63 70 75 69 64 73 64 6b 2e 64 6c 6c 00 51 75 65 72 79 49 6e 74 65 72 66 61 63 65}  //weight: 1, accuracy: High
        $x_1_2 = {66 ad 48 0f b7 c8 c1 e9 0c 66 25 ff 0f 48 85 c9 74 0b 48 0f b7 c9 f3 a4 48 03 f0 eb e3}  //weight: 1, accuracy: High
        $x_1_3 = {58 48 0f b7 c8 48 8d 88 00 03 00 00 c7 01 ?? ?? ?? ?? c7 41 04 ?? ?? ?? ?? 65 48 8b 14 25 60 00 00 00 48 89 51 08 48 8b d3 ff d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

