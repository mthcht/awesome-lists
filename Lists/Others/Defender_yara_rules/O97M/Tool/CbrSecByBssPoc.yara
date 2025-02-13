rule Tool_O97M_CbrSecByBssPoc_246144_0
{
    meta:
        author = "defender2yara"
        detection_name = "Tool:O97M/CbrSecByBssPoc"
        threat_id = "246144"
        type = "Tool"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "CbrSecByBssPoc"
        severity = "Mid"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= ((byIn(i) + Not bEncOrDec) Xor byKey(l)) - bEncOrDec" ascii //weight: 1
        $x_1_2 = "If bEncOrDec Then XorC = \"xxx\" & XorC" ascii //weight: 1
        $x_2_3 = "Put #1, lWritePos, \"CyberSecurityHamburg\"" ascii //weight: 2
        $x_2_4 = "= XorC(strFinal, \"CyberSecurityByBSS\")" ascii //weight: 2
        $x_2_5 = "MsgBox \"RansomwareDetectionTestByBSS\"" ascii //weight: 2
        $x_1_6 = "ElseIf InStr(objFile.Name, \".\") And Not InStr(objFile.Name, \".xlsm\") Then" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

