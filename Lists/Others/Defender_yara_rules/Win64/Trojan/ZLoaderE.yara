rule Trojan_Win64_ZLoaderE_A_2147904362_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ZLoaderE.A"
        threat_id = "2147904362"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ZLoaderE"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6d 28 72 b3 a3 15 78 e2 91 79 1e ad 31 66 ?? b3 57 28 a4 f5 a5 5e da a1 1b 95 b8 8d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

