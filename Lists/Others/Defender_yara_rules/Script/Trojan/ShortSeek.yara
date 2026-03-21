rule Trojan_Script_ShortSeek_GA_2147965303_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Script/ShortSeek.GA!dha"
        threat_id = "2147965303"
        type = "Trojan"
        platform = "Script: "
        family = "ShortSeek"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 20 00 68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 [0-48] 2e 00 [0-48] 2e 00 77 00 6f 00 72 00 6b 00 65 00 72 00 73 00 2e 00 64 00 65 00 76 00 2f 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

