rule Ransom_MSIL_Blacksun_DA_2147768063_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Blacksun.DA!MTB"
        threat_id = "2147768063"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Blacksun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Oops, your important files are encrypted" ascii //weight: 1
        $x_1_2 = "vssadmin delete shadows /all" ascii //weight: 1
        $x_1_3 = "Decryption.key" ascii //weight: 1
        $x_1_4 = ".blacksun" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Blacksun_DB_2147769556_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Blacksun.DB!MTB"
        threat_id = "2147769556"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Blacksun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Oops, your important files are encrypted" ascii //weight: 1
        $x_1_2 = "vssadmin delete shadows /All /Quiet" ascii //weight: 1
        $x_1_3 = "Decryption.key" ascii //weight: 1
        $x_1_4 = "@protonmail.com" ascii //weight: 1
        $x_1_5 = ".blacksun" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

