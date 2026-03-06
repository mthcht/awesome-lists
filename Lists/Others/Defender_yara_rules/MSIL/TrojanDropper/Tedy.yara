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

rule TrojanDropper_MSIL_Tedy_MK_2147964213_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:MSIL/Tedy.MK!MTB"
        threat_id = "2147964213"
        type = "TrojanDropper"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "40"
        strings_accuracy = "High"
    strings:
        $x_20_1 = {07 2d 09 16 8d 1f 00 00 01 0d de 24 07 08 6f 27 00 00 0a 08 6f 28 00 00 0a 0d de 14 08 2c 06 08 6f 23 00 00 0a dc}  //weight: 20, accuracy: High
        $x_15_2 = {6f 15 00 00 0a 26 06 16 06 8e 69 28 16 00 00 0a 14 0a 16 28 17 00 00 0a}  //weight: 15, accuracy: High
        $x_5_3 = "payload.exe" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

