rule Backdoor_MSIL_Predatorpain_SK_2147949092_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Predatorpain.SK!MTB"
        threat_id = "2147949092"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Predatorpain"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {06 07 06 07 91 1f 1d 61 d2 9c 07 17 58 0b 07 06 8e 69 32 ec}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

