rule Virus_O97M_Obfuse_SV_2147932163_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:O97M/Obfuse.SV!MTB"
        threat_id = "2147932163"
        type = "Virus"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "strEngine = UCase$(Application.StartupPath + \"\\\" + cstrEngine)" ascii //weight: 1
        $x_1_2 = "If Len(Dir(Application.StartupPath, vbDirectory)) = 0 Then MkDir Application.StartupPath" ascii //weight: 1
        $x_1_3 = "GetVolumeInformation Left$(strEngine, InStr(1, strEngine, \"\\\")), 0, 0, lngVolumeID, 0, 0, 0, 0" ascii //weight: 1
        $x_1_4 = "Application.ScreenUpdating = True" ascii //weight: 1
        $x_1_5 = "cmdTarget.DeleteLines 1, cmdSource.CountOfLines" ascii //weight: 1
        $x_1_6 = "wbkTarget.CustomDocumentProperties(pptVolume.Name).Value = pptVolume.Value" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

