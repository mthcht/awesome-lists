rule Trojan_Win64_Conti_RDA_2147851687_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Conti.RDA!MTB"
        threat_id = "2147851687"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Conti"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0f b6 85 e8 00 00 00 8d 44 00 3f 99 b9 7f 00 00 00 f7 f9 8b c2 48 8d a5 c8}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

