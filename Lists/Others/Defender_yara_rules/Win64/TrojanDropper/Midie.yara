rule TrojanDropper_Win64_Midie_MK_2147968835_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win64/Midie.MK!MTB"
        threat_id = "2147968835"
        type = "TrojanDropper"
        platform = "Win64: Windows 64-bit platform"
        family = "Midie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "35"
        strings_accuracy = "High"
    strings:
        $x_15_1 = "cpteULYpPNMcWNTubVwxji" ascii //weight: 15
        $x_10_2 = "lJWKNMATTaHbitatlJ" ascii //weight: 10
        $x_5_3 = "QAxqkQXrdkNEGVIiX" ascii //weight: 5
        $x_3_4 = "lUetREuUTciCzTEEaGgr" ascii //weight: 3
        $x_2_5 = "MQXFDvfQuvKNhWlDEjl" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

