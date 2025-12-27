rule Trojan_Win64_ExfilSkip_A_2147945583_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ExfilSkip.A"
        threat_id = "2147945583"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ExfilSkip"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {75 73 65 72 6e 61 6d 65 40 68 ?? 73 74 20 73 6f 75 72 63 65 5f 64 69 72 20 72 65 6d 6f 74 65 5f 70 61 74 68}  //weight: 1, accuracy: Low
        $x_1_2 = "Found %d files totaling %.2f MB (skipped %d files," ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

