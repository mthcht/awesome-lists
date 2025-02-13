rule Ransom_MSIL_Fox_PA_2147739939_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Fox.PA!MTB"
        threat_id = "2147739939"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Fox"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "All your files have been encrypted due to a security problem" ascii //weight: 1
        $x_1_2 = ":\\Users\\Fox\\Desktop\\Fox\\" ascii //weight: 1
        $x_1_3 = "Ran Cripr:" wide //weight: 1
        $x_1_4 = "[Foxdecrypt@protonmail.com].vendetta" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

