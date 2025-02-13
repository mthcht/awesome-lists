rule Trojan_O97M_Netwire_RP_2147831946_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Netwire.RP!MTB"
        threat_id = "2147831946"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Netwire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "(\"exe.QFR/642.491.3.291//:ptth\")" ascii //weight: 1
        $x_1_2 = " = CreateObject(\"WScript.Shell\")" ascii //weight: 1
        $x_1_3 = ".Run \"certutil.exe -urlcache -split -f \" +" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

