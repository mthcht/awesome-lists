rule Trojan_MSIL_Ratx_SM_2147851331_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Ratx.SM!MTB"
        threat_id = "2147851331"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Ratx"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {00 11 04 11 07 09 11 07 91 08 11 07 08 8e 69 5d 91 61 d2 9c 00 11 07 17 58 13 07 11 07 09 8e 69 fe 04 13 08 11 08 2d d8}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Ratx_SN_2147851332_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Ratx.SN!MTB"
        threat_id = "2147851332"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Ratx"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {07 06 08 06 18 5a 18 6f ?? ?? ?? 0a 1f 10 28 ?? ?? ?? 0a d2 9c 06 17 58 0a 06 07 8e 69 fe 04 13 05 11 05 2d db}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Ratx_SP_2147921712_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Ratx.SP!MTB"
        threat_id = "2147921712"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Ratx"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "GiauTM.CSharp.TikiRouter.Properties" ascii //weight: 2
        $x_2_2 = "$2709a7e2-d555-45df-a0fa-588f2abf8d0e" ascii //weight: 2
        $x_1_3 = "RouterConfig.tsv" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

