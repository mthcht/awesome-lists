rule Ransom_MSIL_Trumper_DA_2147773128_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Trumper.DA!MTB"
        threat_id = "2147773128"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Trumper"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Send 0.01 Bitcoin to the following address:" ascii //weight: 1
        $x_1_2 = "DECRYPTION KEY DELETED ON:" ascii //weight: 1
        $x_1_3 = "_Trinity_Obfuscator_" ascii //weight: 1
        $x_1_4 = "Microsoft YaHei" ascii //weight: 1
        $x_1_5 = "Chromio" ascii //weight: 1
        $x_1_6 = "UH OH!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Trumper_SWG_2147925452_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Trumper.SWG!MTB"
        threat_id = "2147925452"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Trumper"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Your MBR has been overwritted and your files encrypted" ascii //weight: 2
        $x_2_2 = "contact me on telegram https://t.me/sh3dddd to get your files back" ascii //weight: 2
        $x_1_3 = "$ab3d0bcb-65e1-488f-91e3-f94aa528cb1a" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

