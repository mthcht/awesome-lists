rule Ransom_MSIL_Majordom_YAA_2147933194_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Majordom.YAA!MTB"
        threat_id = "2147933194"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Majordom"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Oups Your Files Has Ben Encrypted By Majordom Ransomawre" wide //weight: 1
        $x_11_2 = "majordom.Properties.Resources" wide //weight: 11
        $x_1_3 = "Delete Files" wide //weight: 1
        $x_1_4 = "Majordom V4.0\\client\\majordom\\obj\\Debug\\majordom.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

