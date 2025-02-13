rule TrojanDownloader_O97M_Maldoc_HA_2147919980_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Maldoc.HA!MTB"
        threat_id = "2147919980"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Maldoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {53 75 62 20 [0-32] 28 [0-21] 20 41 73 20 53 74 72 69 6e 67 29 [0-32] 44 69 6d 20 [0-21] 20 41 73 20 53 74 72 69 6e 67 [0-32] 44 69 6d 20 [0-21] 20 41 73 20 4f 62 6a 65 63 74 [0-32] 03 20 3d 20 22 63 6d 64 20 2f 63 20 70 6f 77 65 72 73 68 65 6c 6c 20 2d 45 6e 63 6f 64 65 64 43 6f 6d 6d 61 6e 64 20 22 20 26 20 01 [0-32] 53 65 74 20 05 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 [0-32] 05 2e 52 75 6e 20 03 2c 20 30 2c 20 46 61 6c 73 65 [0-32] 45 6e 64 20 53 75 62}  //weight: 2, accuracy: Low
        $x_1_2 = ".CreateElement(\"b64\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

