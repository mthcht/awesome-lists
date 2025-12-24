rule Trojan_Win64_SkuldStealer_ASD_2147960048_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/SkuldStealer.ASD!MTB"
        threat_id = "2147960048"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "SkuldStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c0 ea 04 83 e7 0f c1 e7 04 09 d7 40 88 3c 31 48 ff c6 44 89 c2 48 39 f3 7e 21 89 d7 c1 e2 02 41 89 f8 40 c0 ef 03 09 d7 0f b6 14 30 31 fa 29 f2 0f 1f 40 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

