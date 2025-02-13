rule TrojanDownloader_W97M_Simmerph_A_2147697063_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Simmerph.A"
        threat_id = "2147697063"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Simmerph"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "http://128.65.206.35:555/henro1-cr.exe" ascii //weight: 10
        $x_1_2 = "Array(\"ataDppA\", \"PMET\")" ascii //weight: 1
        $x_1_3 = "StrReverse" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_W97M_Simmerph_B_2147706607_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Simmerph.B"
        threat_id = "2147706607"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Simmerph"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "746870742F3A732F6D696C7072656F647469742E2F6B6F68656D6D2F627973656374736D702F6E6F64656C65652E6578" ascii //weight: 1
        $x_1_2 = "O = Array(\"ataDppA\", \"PMET\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

