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

rule Ransom_MSIL_Lockscreen_SLDR_2147952277_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Lockscreen.SLDR!MTB"
        threat_id = "2147952277"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lockscreen"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {02 7b b4 00 00 04 72 3e 0d 00 70 72 42 0d 00 70 6f 84 01 00 0a 72 46 0d 00 70 28 87 01 00 0a 0a 1b 8d 63 00 00 01 25 16 72 ?? 0e 00 70 a2 25 17 72 ?? 0e 00 70 a2}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

