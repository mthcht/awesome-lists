rule TrojanDownloader_MSIL_Wisntes_A_2147686115_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Wisntes.A"
        threat_id = "2147686115"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Wisntes"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 00 53 74 61 72 74 00}  //weight: 1, accuracy: High
        $x_1_2 = "/tracker/script.php?user=" wide //weight: 1
        $x_1_3 = {1f 1d 0f 00 1a 28 ?? 00 00 06}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Wisntes_B_2147686338_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Wisntes.B"
        threat_id = "2147686338"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Wisntes"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "DisableSR" wide //weight: 1
        $x_1_2 = "DisableRegistryTools" wide //weight: 1
        $x_1_3 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 00 53 74 61 72 74 00}  //weight: 1, accuracy: High
        $x_1_4 = {1f 1d 12 00 1a 28 ?? 00 00 06}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

