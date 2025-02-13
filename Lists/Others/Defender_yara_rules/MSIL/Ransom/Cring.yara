rule Ransom_MSIL_Cring_DA_2147779244_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Cring.DA!MTB"
        threat_id = "2147779244"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cring"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "your network is encrypted" ascii //weight: 1
        $x_1_2 = "Crypt3r" ascii //weight: 1
        $x_1_3 = "@tutanota.com" ascii //weight: 1
        $x_1_4 = "killme.bat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

