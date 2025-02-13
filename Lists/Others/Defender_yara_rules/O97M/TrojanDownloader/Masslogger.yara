rule TrojanDownloader_O97M_Masslogger_PM_2147769082_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Masslogger.PM!MTB"
        threat_id = "2147769082"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Masslogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Call Shell$(\"rEGsvR32" ascii //weight: 1
        $x_1_2 = "-i:https://via.hypothes.is/boyama.medyanef.com/vendor/phpunit/phpunit/src/Util/Log/Bc.wsc" ascii //weight: 1
        $x_1_3 = "SCroBJ.Dll" ascii //weight: 1
        $x_1_4 = "Sub DoCuMENT_OPen(): Call" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

