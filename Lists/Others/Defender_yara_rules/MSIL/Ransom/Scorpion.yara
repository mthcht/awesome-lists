rule Ransom_MSIL_Scorpion_MK_2147795783_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Scorpion.MK!MTB"
        threat_id = "2147795783"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Scorpion"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Scorpion Ransomware" ascii //weight: 1
        $x_1_2 = "FILES WILL BE DELETED IN:" ascii //weight: 1
        $x_1_3 = "PAYMENT RAISE IN:" ascii //weight: 1
        $x_1_4 = "All Your Files Are Now Fully Deleted" ascii //weight: 1
        $x_1_5 = "OOPS YOU HAVE BEEN INFECTED" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

