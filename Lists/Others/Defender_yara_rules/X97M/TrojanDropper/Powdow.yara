rule TrojanDropper_X97M_Powdow_SG_2147828776_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:X97M/Powdow.SG!MSR"
        threat_id = "2147828776"
        type = "TrojanDropper"
        platform = "X97M: Excel 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Powdow"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "If OB.FileExists(Environ(\"temp\") & \"\\nvidiax.exe\") = True Then" ascii //weight: 1
        $x_1_2 = "OB.DeleteFile Environ(\"temp\") & \"\\nvidiax.exe" ascii //weight: 1
        $x_1_3 = "SX = SX & Worksheets(\"Final Offer\").Range(\"bs\" & i).Value" ascii //weight: 1
        $x_1_4 = "SX = Trim(StrReverse(SX))" ascii //weight: 1
        $x_1_5 = "objNode.DataType = \"bin.base64" ascii //weight: 1
        $x_1_6 = "VBA.CreateObject(\"WScript.Shell\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

