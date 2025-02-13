rule Ransom_MSIL_karma_DA_2147767364_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/karma.DA!MTB"
        threat_id = "2147767364"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "karma"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Your files have been encrypted" ascii //weight: 1
        $x_1_2 = "DECRYPT MY FILES" ascii //weight: 1
        $x_1_3 = "karma Decryptor" ascii //weight: 1
        $x_1_4 = "karma Ransomware" ascii //weight: 1
        $x_1_5 = "Team Karma" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

