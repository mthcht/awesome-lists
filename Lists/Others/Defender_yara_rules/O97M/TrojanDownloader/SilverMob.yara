rule TrojanDownloader_O97M_SilverMob_A_2147724639_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/SilverMob.A!dha"
        threat_id = "2147724639"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "SilverMob"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Chr(46 + (Asc(" ascii //weight: 1
        $x_1_2 = ") - 46 - 20 + (122 - 46)) Mod (122 - 46))" ascii //weight: 1
        $x_1_3 = "\"a1w:7;7.<Bla`\\hhd\"" ascii //weight: 1
        $x_1_4 = "\"UXcXVBg<:yu5\"" ascii //weight: 1
        $x_1_5 = "\"gw:18<16/BZ14ygA;<y5cv2yw<\"" ascii //weight: 1
        $x_1_6 = "VBA.CreateObject(\"W\" + \"Sc\" + \"r\" + \"ip\" + \"t\" + \".S\" + \"h\" + \"el\" + \"l\")" ascii //weight: 1
        $x_1_7 = "\"p;>w07;<By@y\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

