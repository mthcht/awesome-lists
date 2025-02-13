rule TrojanSpy_MSIL_Tedy_ATY_2147847987_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Tedy.ATY!MTB"
        threat_id = "2147847987"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {16 0c 2b 3d 00 08 28 ?? ?? ?? 06 0d 09 17 2e 0a 09 20 01 80 00 00 fe 01 2b 01 17 13 04 11 04 2c 1b 00 07 72 01 00 00 70 08 d1 8c 13 00 00 01 28}  //weight: 2, accuracy: Low
        $x_1_2 = "keylogger.log" wide //weight: 1
        $x_1_3 = "GetKeys" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

