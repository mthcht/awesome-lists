rule HackTool_MSIL_Rubeus_RDA_2147848753_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MSIL/Rubeus.RDA!MTB"
        threat_id = "2147848753"
        type = "HackTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rubeus"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Rubeus" ascii //weight: 1
        $x_1_2 = "minibeus" ascii //weight: 1
        $x_1_3 = "KrbCredInfo" ascii //weight: 1
        $x_1_4 = "AsnElt" ascii //weight: 1
        $x_1_5 = "EncryptedPAData" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_MSIL_Rubeus_PSUM_2147897052_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MSIL/Rubeus.PSUM!MTB"
        threat_id = "2147897052"
        type = "HackTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rubeus"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {02 03 11 08 03 59 28 ?? 06 00 06 13 09 03 11 09 7b d4 02 00 04 58 10 01 11 07 11 09 6f ?? 01 00 0a 03 11 08 32 da}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

