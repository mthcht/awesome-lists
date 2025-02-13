rule TrojanDownloader_O97M_Arkei_YA_2147758346_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Arkei.YA!MTB"
        threat_id = "2147758346"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Arkei"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ShellExecute Lib \"shell32.dll\" Alias \"ShellExecuteA" ascii //weight: 1
        $x_1_2 = "ShellExecute(Scr_hDC, \"Open\", DocName, \"\", \"C:\\" ascii //weight: 1
        $x_1_3 = "startDoc(saveFolder & \"\\Gerta.vbs\")" ascii //weight: 1
        $x_1_4 = "saveFolder & \"\\Gerta.cmd\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_O97M_Arkei_ASG_2147819457_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Arkei.ASG!MSR"
        threat_id = "2147819457"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Arkei"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\\\Users\\\\Public\\\\servicehomework.e^xe" ascii //weight: 1
        $x_1_2 = "cugdwpnykghx.ru/bq979g5dfwbn31q91tq.bn31q91t^xbn31q91t -o" ascii //weight: 1
        $x_1_3 = "/p c:\\windows\\system32 /m notepad.exe /c" ascii //weight: 1
        $x_1_4 = "bella.lnk" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

