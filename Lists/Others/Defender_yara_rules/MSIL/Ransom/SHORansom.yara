rule Ransom_MSIL_SHORansom_YAB_2147852984_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/SHORansom.YAB!MTB"
        threat_id = "2147852984"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SHORansom"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "S.H.O" wide //weight: 1
        $x_1_2 = "Readme.txt" wide //weight: 1
        $x_1_3 = "files are stolen and encrypted" wide //weight: 1
        $x_1_4 = "RSAKeyValue" wide //weight: 1
        $x_1_5 = "PC has succumbed to my wicked grasp" wide //weight: 1
        $x_1_6 = "kindely decrypt your files" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

