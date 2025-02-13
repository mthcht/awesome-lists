rule Trojan_O97M_EhnsAbuse_A_2147740940_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/EhnsAbuse.A"
        threat_id = "2147740940"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EhnsAbuse"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Sheet1.Anykey" ascii //weight: 1
        $x_5_2 = {73 61 76 65 74 6f 66 69 6c 65 20 [0-8] 2e 65 22 20 26 20 22 78 65 22 2c 20 32}  //weight: 5, accuracy: Low
        $x_1_3 = "ExecuteExcel4Macro" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

