rule TrojanDownloader_VBS_Squiblydoo_AN_2147752522_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:VBS/Squiblydoo.AN!MTB"
        threat_id = "2147752522"
        type = "TrojanDownloader"
        platform = "VBS: Visual Basic scripts"
        family = "Squiblydoo"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "WScript.Shell" ascii //weight: 1
        $x_1_2 = "WiNmGmTs:{ImPeRsOnAtIoNlEvEl=ImPeRsOn" ascii //weight: 1
        $x_2_3 = {72 65 67 73 76 72 33 32 20 2f 75 20 2f 6e 20 2f 73 20 2f 69 3a (68 74|68 74 74) 3a 2f 2f [0-37] 20 73 63 72 6f 62 6a 2e 64 6c 6c}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

