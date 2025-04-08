rule Trojan_Win64_Boldbadger_GA_2147938144_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Boldbadger.GA!MTB"
        threat_id = "2147938144"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Boldbadger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c6 44 24 60 61 c6 44 24 61 63 c6 44 24 62 39 c6 44 24 63 5a c6 44 24 64 73 c6 44 24 65 77 c6 44 24 66 00}  //weight: 1, accuracy: High
        $x_2_2 = {32 84 19 dc 78 1c 00 48 8b 54 24 38 88 04 0a 48 83 c1 01 48 39 4c 24 40 77 ba}  //weight: 2, accuracy: High
        $x_1_3 = {48 89 c8 49 89 c8 48 89 cf 49 f7 e1 49 29 d0 49 d1 e8 4c 01 c2 48 c1 ea 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

