rule Trojan_MSIL_Mimpe_RS_2147899222_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Mimpe.RS!MTB"
        threat_id = "2147899222"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Mimpe"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell_reflective_mimikatz" wide //weight: 1
        $x_1_2 = "get_MimikatzPE" ascii //weight: 1
        $x_1_3 = "set_MimikatzPE" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

