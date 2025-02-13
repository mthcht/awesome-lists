rule TrojanDownloader_O97M_StealthFalcon_2147712202_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/StealthFalcon!dha"
        threat_id = "2147712202"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "StealthFalcon"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CreateObject(\"WScript.Shell\").Run \"powershell -ex bypass -nop -w hidden -noni -e dAByAHkADQAKAHsADQAKACAAIAAgACAAJABwAG" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

