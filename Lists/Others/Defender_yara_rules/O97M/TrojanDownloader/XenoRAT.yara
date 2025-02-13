rule TrojanDownloader_O97M_XenoRAT_QBAA_2147914301_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/XenoRAT.QBAA!MTB"
        threat_id = "2147914301"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "XenoRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "subworkbook_open()dimwshshellasobjectdimztihspecialpathjinaasstringdimasinteger=chr(50)+chr(48)+chr(48)" ascii //weight: 1
        $x_1_2 = "setwshshell=createobject(\"wscript.shell\")" ascii //weight: 1
        $x_1_3 = "ztihspecialpathjina=wshshell.specialfolders(\"recent\")" ascii //weight: 1
        $x_1_4 = "set=createobject(\"microsoft.xmlhttp\")" ascii //weight: 1
        $x_1_5 = "set=createobject(\"shell.application\")" ascii //weight: 1
        $x_1_6 = "=ztihspecialpathjina+(\"\\mjqnzv.\").open\"get\",(\"h://www.bglv./db-/vg/j.\")" ascii //weight: 1
        $x_1_7 = "status=200thenset=createobject(\"adodb.stream\").open.type=.write.savetofile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

