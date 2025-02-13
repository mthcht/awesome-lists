rule Virus_Win64_Sobelow_A_2147651320_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win64/Sobelow.A"
        threat_id = "2147651320"
        type = "Virus"
        platform = "Win64: Windows 64-bit platform"
        family = "Sobelow"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {51 65 ff 34 25 80 14 00 00 53 56 57 41 50 41 51 c8 98 02 00 6a 00 e8 4e 00 00 00 68 d3 96 11 fa d9 a0 4b 64 1e 17 22 2e 7c ea a8 a8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

