rule PWS_MSIL_Disstl_ABJ_2147829606_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Disstl.ABJ!MTB"
        threat_id = "2147829606"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Disstl"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_6_1 = {57 d5 02 28 09 02 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 22 00 00 00 6a 02 00 00 04 00 00 00 cd 04 00 00 02 00 00 00 21 00 00 00}  //weight: 6, accuracy: High
        $x_1_2 = "GetRuntimeDirectory" ascii //weight: 1
        $x_1_3 = "GetCommandLineArgs" ascii //weight: 1
        $x_1_4 = "Combine" ascii //weight: 1
        $x_1_5 = "CreateDecryptor" ascii //weight: 1
        $x_1_6 = "TransformFinalBlock" ascii //weight: 1
        $x_1_7 = "Q29yb25vdmlydXMuQ29yb25vdmlydXM=" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_MSIL_Disstl_AD_2147838634_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Disstl.AD!MTB"
        threat_id = "2147838634"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Disstl"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {08 0d 16 13 04 2b 36 09 11 04 9a 73 3b 00 00 0a 6f 3c 00 00 0a 28 3d 00 00 0a 13 05 07 11 05 6f 3e 00 00 0a 13 06 11 06 6f 3f 00 00 0a 2c 08 11 06 6f 40 00 00 0a 0a 11 04 17 58 13 04 11 04 09 8e 69 32 c3}  //weight: 2, accuracy: High
        $x_1_2 = "Growtopia_Save_Stealer" ascii //weight: 1
        $x_1_3 = "taskkill /f /im" wide //weight: 1
        $x_1_4 = "Windows\\ClipperClipboard.txt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

