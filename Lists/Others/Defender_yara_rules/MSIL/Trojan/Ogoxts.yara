rule Trojan_MSIL_Ogoxts_MA_2147898554_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Ogoxts.MA!MTB"
        threat_id = "2147898554"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Ogoxts"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {07 08 06 08 9a 1f 10 28 53 00 00 0a 9c 08 17 58 0c 08 06 8e 69 32 e9 07 2a}  //weight: 5, accuracy: High
        $x_1_2 = "DLL_PROCESS_ATTACH" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

