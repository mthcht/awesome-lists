rule Trojan_MSIL_Rubeus_NR_2147937185_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rubeus.NR!MTB"
        threat_id = "2147937185"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rubeus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {08 6f df 06 00 06 16 9a 6f 04 07 00 06 28 f0 06 00 06 6f df 06 00 06 16 9a 14 73 1a 01 00 06}  //weight: 2, accuracy: High
        $x_1_2 = {6f df 06 00 06 17 9a 6f df 06 00 06 16 9a 6f 04 07 00 06}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

