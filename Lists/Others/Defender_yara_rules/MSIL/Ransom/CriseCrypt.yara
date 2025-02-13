rule Ransom_MSIL_CriseCrypt_DA_2147799119_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/CriseCrypt.DA!MTB"
        threat_id = "2147799119"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CriseCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "crise-crypt" ascii //weight: 1
        $x_1_2 = "Starting encryption" ascii //weight: 1
        $x_1_3 = "/C NetSh Advfirewall set allprofiles state off" ascii //weight: 1
        $x_1_4 = ".compressed" ascii //weight: 1
        $x_1_5 = "costura" ascii //weight: 1
        $x_1_6 = ".crypt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

