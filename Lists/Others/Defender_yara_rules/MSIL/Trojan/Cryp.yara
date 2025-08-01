rule Trojan_MSIL_Cryp_SK_2147948146_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Cryp.SK!MTB"
        threat_id = "2147948146"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryp"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {08 09 d6 0b 09 0c 07 0d 11 0f 17 d6 13 0f 11 0f 1f 5a 31 ec}  //weight: 2, accuracy: High
        $x_2_2 = "FabtomPard.Resources" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

