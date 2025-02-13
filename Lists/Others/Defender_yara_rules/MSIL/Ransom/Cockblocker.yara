rule Ransom_MSIL_Cockblocker_DA_2147768387_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Cockblocker.DA!MTB"
        threat_id = "2147768387"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cockblocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Hi Reverseing Engineers! I hate people who are too lazy to make their own ransomware" ascii //weight: 1
        $x_1_2 = "Close via TaskMgr now if you do not want your files encrypted!" ascii //weight: 1
        $x_1_3 = "RansomwareDisplay" ascii //weight: 1
        $x_1_4 = "Cockblocker" ascii //weight: 1
        $x_1_5 = "it's not fucking Razy" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

