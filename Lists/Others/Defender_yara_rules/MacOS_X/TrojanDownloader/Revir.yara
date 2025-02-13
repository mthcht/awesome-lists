rule TrojanDownloader_MacOS_X_Revir_A_2147649886_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MacOS_X/Revir.A"
        threat_id = "2147649886"
        type = "TrojanDownloader"
        platform = "MacOS_X: "
        family = "Revir"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "curl -o /tmp/updtdata" ascii //weight: 1
        $x_3_2 = {55 89 e5 83 ec 18 e8 8b ff ff ff c7 44 24 04 ?? ?? 00 00 a1 28 20 00 00 89 04 24 e8 a3 00 00 00 c7 04 24 ?? ?? 00 00 e8 c7 00 00 00 c7 44 24}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MacOS_X_Revir_B_2147656196_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MacOS_X/Revir.B"
        threat_id = "2147656196"
        type = "TrojanDownloader"
        platform = "MacOS_X: "
        family = "Revir"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ".jpg" ascii //weight: 1
        $x_1_2 = ".pdf" ascii //weight: 1
        $x_1_3 = "start!" ascii //weight: 1
        $x_1_4 = "/tmp/" ascii //weight: 1
        $x_1_5 = "open self" ascii //weight: 1
        $x_5_6 = {c7 44 24 04 ff 01 00 00 [0-16] 89 04 24 e8 ?? ?? 00 00 c7 04 24}  //weight: 5, accuracy: Low
        $x_5_7 = {01 ff 7e a3 ab 78 48 00 00 41 38 76 1e f4 48 00 01 39}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 3 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

