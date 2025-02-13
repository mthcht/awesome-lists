rule TrojanDownloader_O97M_AveMaria_BAK_2147776214_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/AveMaria.BAK!MTB"
        threat_id = "2147776214"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "musa = \"\"\"m\" + \"s\" + \"h\" + \"ta\"\"\"\"" ascii //weight: 1
        $x_1_2 = "http://%20%20%20%2020%2020%2020%2020%20@bit.ly/4knaskn4kand\"\"\"" ascii //weight: 1
        $x_1_3 = "= Split(Replace(pTags, \" \", \"\"), \",\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_AveMaria_SS_2147784813_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/AveMaria.SS!MTB"
        threat_id = "2147784813"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 63 65 72 43 61 6c 6c 2e 4f 6c 6c 65 79 20 3d 20 22 68 74 74 70 3a 2f 2f 77 77 77 2e 22 0d 0a 41 63 65 72 43 61 6c 6c 2e 4f 62 6a 65 63 74 49 6e 73 74 61 6e 74 20 3d 20 22 62 69 74 6c 79 2e 63 6f 6d 2f 61 73 68 6a 64 6b 71 6f 77 64 68 71 6f 77 64 68}  //weight: 1, accuracy: High
        $x_1_2 = "NewCalls.SqlSussyCall (AcerCall.Jonas + AcerCall.Martha + AcerCall.Noah + AcerCall.Adam)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

