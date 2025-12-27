rule TrojanDropper_MSIL_Tedy_ARR_2147958802_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:MSIL/Tedy.ARR!MTB"
        threat_id = "2147958802"
        type = "TrojanDropper"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_15_1 = {07 2d 63 08 28 ?? ?? ?? ?? 2d 5b 08 28}  //weight: 15, accuracy: Low
        $x_8_2 = {13 09 12 09 28 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 34 02 17 0b de 03}  //weight: 8, accuracy: Low
        $x_5_3 = "-WindowStyle Hidden -ExecutionPolicy Bypass -NoProfile -NoLogo -File" ascii //weight: 5
        $x_2_4 = "msupdate.tmp" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

