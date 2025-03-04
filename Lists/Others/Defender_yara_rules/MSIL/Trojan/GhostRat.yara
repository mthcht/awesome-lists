rule Trojan_MSIL_GhostRAT_NG_2147923059_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/GhostRAT.NG!MTB"
        threat_id = "2147923059"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "GhostRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {28 80 00 00 0a 72 6c 07 00 70 6f 92 00 00 0a 0c 07 8e 69 8d 64 00 00 01 0d 16 13 06 2b 18 09 11 06 07 11 06 91 08 11 06 08 8e 69 5d 91 61 d2 9c 11 06 17 58 13 06 11 06 07 8e 69 32 e1 20 d0 07 00 00 28 93 00 00 0a 7e 94 00 00 0a 09 8e 69 20 00 10 00 00 1f 40 28 34 00 00 06}  //weight: 3, accuracy: High
        $x_2_2 = {11 08 6f 86 00 00 0a d4 8d 64 00 00 01 13 09 11 08 11 09 16 11 09 8e 69 6f 87 00 00 0a 26 08 11 09 28 88 00 00 0a de 18}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

