rule TrojanDownloader_O97M_Adwind_MK_2147769476_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Adwind.MK!MTB"
        threat_id = "2147769476"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Adwind"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "h%^t%^t%^p%^:%^/%^/%^l%^i%^m%^i%^t%^e%^d%^e%^d%^i%^t%^i%^o%^n%^p%^h%^o%^t%^o%^s%^.%^n%^l" ascii //weight: 1
        $x_1_2 = "tt = Replace(tt, \"%^\", \"\")" ascii //weight: 1
        $x_1_3 = "cc = String" ascii //weight: 1
        $x_1_4 = "ShellObj.ShellExecute cc, tt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

