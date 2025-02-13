rule Trojan_O97M_Vobfush_A_2147731167_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Vobfush.A"
        threat_id = "2147731167"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Vobfush"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "17"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {20 2f 20 54 61 6e 28 20 00 e0 00 20 3d 20 28 10 00 20 2b 20 52 6f 75 6e 64 28 20 00 29 20 2a 20 10 00 20 2d 20 20 00 20 2b 20 28}  //weight: 10, accuracy: Low
        $x_5_2 = "Shell" ascii //weight: 5
        $x_1_3 = "Shapes" ascii //weight: 1
        $x_1_4 = "TextFrame" ascii //weight: 1
        $x_1_5 = "TextRange" ascii //weight: 1
        $x_1_6 = "Interaction" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

