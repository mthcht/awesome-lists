rule Backdoor_MSIL_Tedy_AR_2147954237_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Tedy.AR!MTB"
        threat_id = "2147954237"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_15_1 = {0c 02 08 06 28 [0-16] 09 8e 69 20 ?? ?? ?? 00 1f 40 28 ?? ?? ?? ?? 13 04 09 16 11 04}  //weight: 15, accuracy: Low
        $x_5_2 = {0b 00 07 03 16 03 8e 69 6f ?? ?? ?? ?? 0c de 20 07}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

