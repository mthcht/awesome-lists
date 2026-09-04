rule TrojanDropper_MSIL_Heracles_VDE_2147964742_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:MSIL/Heracles.VDE!MTB"
        threat_id = "2147964742"
        type = "TrojanDropper"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "FUCK_IS_ALWAYS_REAL" ascii //weight: 5
        $x_5_2 = "DRIERSSSS_LOAD_AUTO_IN_PROCESSS" ascii //weight: 5
        $x_5_3 = "AndroidProcess.exe" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_MSIL_Heracles_AB_2147977485_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:MSIL/Heracles.AB!MTB"
        threat_id = "2147977485"
        type = "TrojanDropper"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_6_1 = {28 11 00 00 0a 13 04 09 06 28 12 00 00 0a 11 04 07 28 12 00 00 0a 09 28 13 00 00 0a 26 11 04 28 13 00 00 0a 26}  //weight: 6, accuracy: High
        $x_3_2 = "TVqQAAMAAAAEAAAA" wide //weight: 3
        $x_2_3 = "GetTempPath" ascii //weight: 2
        $x_2_4 = "FromBase64String" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

