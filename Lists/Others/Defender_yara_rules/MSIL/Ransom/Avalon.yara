rule Ransom_MSIL_Avalon_DA_2147781637_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Avalon.DA!MTB"
        threat_id = "2147781637"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Avalon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Your files are encrypted" ascii //weight: 1
        $x_1_2 = "Avalon Ransomware" ascii //weight: 1
        $x_1_3 = "@protonmail.com" ascii //weight: 1
        $x_1_4 = ".avalon" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

