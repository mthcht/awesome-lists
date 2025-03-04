rule Ransom_MSIL_Lockscreen_2147682527_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Lockscreen"
        threat_id = "2147682527"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lockscreen"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Your unlock code goes here" wide //weight: 1
        $x_1_2 = "Unlock" wide //weight: 1
        $x_1_3 = "Your computer was unlocked with" wide //weight: 1
        $x_1_4 = "ElmerLock" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

