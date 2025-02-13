rule Trojan_O97M_TrojanDownloader_RDA_2147838722_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/TrojanDownloader.RDA!MTB"
        threat_id = "2147838722"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "TrojanDownloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "//192.168.41.128/powercat.ps1" ascii //weight: 1
        $x_1_2 = "-p 1337" ascii //weight: 1
        $x_1_3 = "-e cmd" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_O97M_TrojanDownloader_RDB_2147838723_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/TrojanDownloader.RDB!MTB"
        threat_id = "2147838723"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "TrojanDownloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "MwAuADYAOAAuADUANgAuADIAMwAyACIALAAxADIANAA0ADEAKQ" ascii //weight: 2
        $x_2_2 = "powershell -e" ascii //weight: 2
        $x_2_3 = "CreateObject(\"Wscript.shell\").Run" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

