rule TrojanDownloader_W97M_Wopert_A_2147708238_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Wopert.A"
        threat_id = "2147708238"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Wopert"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "decrypt(Decode64(\"" ascii //weight: 3
        $x_8_2 = "(((UBound(bIn) + 1) \\ 4) * 3) - 1)" ascii //weight: 8
        $x_2_3 = "= ActiveDocument.BuiltInDocumentProperties(" ascii //weight: 2
        $x_2_4 = "Mid(strInput, first, 1) = Chr(" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_W97M_Wopert_B_2147743696_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Wopert.B"
        threat_id = "2147743696"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Wopert"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Function decrypt(" ascii //weight: 2
        $x_2_2 = "var0 = decrypt(" ascii //weight: 2
        $x_1_3 = "Var = var0" ascii //weight: 1
        $x_2_4 = "Shell (Var)" ascii //weight: 2
        $x_1_5 = "Sub Auto_Open()" ascii //weight: 1
        $x_2_6 = "Mid(strInput, first, 1) = Chr(Asc(Mid" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            (all of ($x*))
        )
}

