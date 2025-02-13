rule Trojan_Win64_Bast_A_2147926988_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bast.A"
        threat_id = "2147926988"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bast"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 73 69 64 65 6c 6f 61 64 2e 70 64 62 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

