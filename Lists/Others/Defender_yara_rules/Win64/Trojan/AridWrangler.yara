rule Trojan_Win64_AridWrangler_A_2147962900_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AridWrangler.A"
        threat_id = "2147962900"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AridWrangler"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {f2 0f 11 44 24 40 f2 0f 10 44 24 40 f2 0f 59 c6 e8 ?? ?? ?? 00 8b 83 1a f6 03 00 3b 05 ?? ?? ?? 00 f2 0f 11 44 24 40 74}  //weight: 10, accuracy: Low
        $x_10_2 = {f2 0f 10 4c 24 40 8b 83 1a f6 03 00 3b 05 ?? ?? ?? 00 f2 0f 59 ce f2 0f 11 4c 24 40 74}  //weight: 10, accuracy: Low
        $x_1_3 = {00 00 00 48 8b d8 eb 00 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

