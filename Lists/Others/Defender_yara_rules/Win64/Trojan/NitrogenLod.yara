rule Trojan_Win64_NitrogenLod_A_2147894674_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/NitrogenLod.A"
        threat_id = "2147894674"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "NitrogenLod"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {49 ba 47 65 74 50 72 6f 63 41 49 bb 41 64 64 72 65 73 73 00}  //weight: 1, accuracy: High
        $x_1_2 = {49 ba 4c 6f 61 64 4c 69 62 72 49 bb 69 62 72 61 72 79 41 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_NitrogenLod_B_2147907312_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/NitrogenLod.B"
        threat_id = "2147907312"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "NitrogenLod"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 ba 47 65 74 50 72 6f 63 41 49 ?? 41 64 64 72 65 73 73}  //weight: 1, accuracy: Low
        $x_1_2 = {49 ba 4c 6f 61 64 4c 69 62 72 49 bb 69 62 72 61 72 79 41 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

