rule Trojan_MSIL_KillAV_NA_2147926692_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/KillAV.NA!MTB"
        threat_id = "2147926692"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "KillAV"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {07 09 8e 69 09 16 7e 28 00 00 0a 16 7e 28 00 00 0a 28 04 00 00 06 2c 08 07 28 07 00 00 06}  //weight: 3, accuracy: High
        $x_2_2 = {8d 07 00 00 02 13 06 07 12 04 12 05 11 06 12 07 28 05 00 00 06 26 07 17 7e 28 00 00 0a 28 06 00 00 06 26 2a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

