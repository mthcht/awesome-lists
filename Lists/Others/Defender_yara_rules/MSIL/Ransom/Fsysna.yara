rule Ransom_MSIL_Fsysna_DA_2147789041_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Fsysna.DA!MTB"
        threat_id = "2147789041"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Fsysna"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Your Computer Has Been Compromised!" ascii //weight: 1
        $x_1_2 = "vssadmin delete shadows /all /quiet" ascii //weight: 1
        $x_1_3 = "@protonmail.com" ascii //weight: 1
        $x_1_4 = "EncryptedKey" ascii //weight: 1
        $x_1_5 = "Bitcoin Address" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

