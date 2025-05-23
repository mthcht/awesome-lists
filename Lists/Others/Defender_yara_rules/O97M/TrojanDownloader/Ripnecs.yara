rule TrojanDownloader_O97M_Ripnecs_A_2147689949_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Ripnecs.A"
        threat_id = "2147689949"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Ripnecs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Shell(Environ(Base64Decode(\"VGVtcA==\"))" ascii //weight: 1
        $x_1_2 = "CreateObject(Base64Decode(\"TWljcm9zb2Z0LlhNTEhUVFA=\"))" ascii //weight: 1
        $x_1_3 = "Open Base64Decode(\"R0VU\")" ascii //weight: 1
        $x_1_4 = "CreateObject(Base64Decode(\"QURPREIuU3RyZWFt\"))" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

