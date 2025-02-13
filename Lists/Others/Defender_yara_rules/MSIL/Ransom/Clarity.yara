rule Ransom_MSIL_Clarity_DA_2147769565_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Clarity.DA!MTB"
        threat_id = "2147769565"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Clarity"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WannaClarity" ascii //weight: 1
        $x_1_2 = "To decrypt your files you need to purchase an decryption key." ascii //weight: 1
        $x_1_3 = ".clarity" ascii //weight: 1
        $x_1_4 = "Finished!, close it with your Taskmanager!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

