rule Trojan_MSIL_Rootkit_SNA_2147968909_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rootkit.SNA!MTB"
        threat_id = "2147968909"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rootkit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {11 07 11 08 11 06 11 08 16 6f 8c 00 00 0a 13 09 12 09 28 8d 00 00 0a 9c 11 08 17 58 13 08 11 08 11 06 6f 8b 00 00 0a 32 d7}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

