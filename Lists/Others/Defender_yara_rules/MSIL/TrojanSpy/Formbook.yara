rule TrojanSpy_MSIL_Formbook_MK_2147771479_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Formbook.MK!MTB"
        threat_id = "2147771479"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "NT1.dll" ascii //weight: 1
        $x_1_2 = "malheureux" ascii //weight: 1
        $x_1_3 = "get_Jonas" ascii //weight: 1
        $x_1_4 = "set_Jonas" ascii //weight: 1
        $x_1_5 = "GetData" ascii //weight: 1
        $x_1_6 = "GetExecutingAssembly" ascii //weight: 1
        $x_1_7 = "GetEntryAssembly" ascii //weight: 1
        $x_1_8 = "get_Evidence" ascii //weight: 1
        $x_1_9 = "GetManifestResourceNames" ascii //weight: 1
        $x_1_10 = "GetBytes" ascii //weight: 1
        $x_1_11 = "SetData" ascii //weight: 1
        $x_1_12 = "Read" ascii //weight: 1
        $x_1_13 = "ToArray" ascii //weight: 1
        $x_1_14 = "get_Width" ascii //weight: 1
        $x_1_15 = "get_Length" ascii //weight: 1
        $x_1_16 = "GetPixel" ascii //weight: 1
        $x_1_17 = "BitConverter" ascii //weight: 1
        $x_1_18 = "ToInt32" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

