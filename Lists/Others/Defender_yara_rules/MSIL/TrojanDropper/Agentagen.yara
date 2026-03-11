rule TrojanDropper_MSIL_Agentagen_VD_2147964539_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:MSIL/Agentagen.VD!MTB"
        threat_id = "2147964539"
        type = "TrojanDropper"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Agentagen"
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

