rule Trojan_Win64_PawFall_A_2147943819_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/PawFall.A"
        threat_id = "2147943819"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "PawFall"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 00 53 00 45 00 56 00 45 00 4e 00 37 00 37 00 37 00 37 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 56 69 72 74 75 61 6c 41 6c 6c 6f 63 00}  //weight: 1, accuracy: High
        $x_2_3 = {c1 ea 04 6b ?? 42 2b ?? 48 ?? ?? 42 0f b6 ?? ?? (41|30)}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

