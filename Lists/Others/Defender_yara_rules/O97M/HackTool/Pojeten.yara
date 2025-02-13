rule HackTool_O97M_Pojeten_B_2147787572_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:O97M/Pojeten.B!MTB"
        threat_id = "2147787572"
        type = "HackTool"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Pojeten"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "CreateObject(\"WScript.Shell" ascii //weight: 1
        $x_1_2 = "\\\\Excel\\\\Security\\\\AccessVBOM" ascii //weight: 1
        $x_1_3 = "CreateObject(\"Microsoft.XMLHTTP" ascii //weight: 1
        $x_1_4 = "CreateObject(\"ADODB.Stream" ascii //weight: 1
        $x_1_5 = {2e 57 72 69 74 65 [0-32] 2e 72 65 73 70 6f 6e 73 65 42 6f 64 79}  //weight: 1, accuracy: Low
        $x_1_6 = "CreateObject(\"Excel.Application" ascii //weight: 1
        $x_1_7 = ".RegisterXLL(" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

