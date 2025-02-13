rule TrojanDownloader_O97M_FormBook_RV_2147922198_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/FormBook.RV!MTB"
        threat_id = "2147922198"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {64 6f 63 75 6d 65 6e 74 5f 6f 70 65 6e 28 29 6f 6e 65 72 72 6f 72 67 6f 74 6f 65 31 63 6f 6e 73 74 75 61 73 73 74 72 69 6e 67 3d 22 68 74 74 70 73 3a 2f 2f 63 64 6e 2e 64 69 73 63 6f 72 64 61 70 70 2e 63 6f 6d 2f 61 74 74 61 63 68 6d 65 6e 74 73 2f 31 32 38 38 36 34 38 37 39 39 32 32 30 34 30 30 32 34 34 2f 31 32 38 38 36 35 31 31 34 39 39 35 31 36 33 35 34 39 36 2f [0-15] 2e 65 78 65 3f 65 78 3d}  //weight: 1, accuracy: Low
        $x_1_2 = "=environ$(\"temp\")&\"\\f\"&right(\"0000\"&cstr(int(rnd()*10000)),4)&\".exe\"" ascii //weight: 1
        $x_1_3 = "=createobject(\"msxml2.xmlhttp\")h.open\"get\",d,falseh.send" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

