rule TrojanDownloader_Script_CosmicPulse_BC_2147951584_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Script/CosmicPulse.BC!dha"
        threat_id = "2147951584"
        type = "TrojanDownloader"
        platform = "Script: "
        family = "CosmicPulse"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 00 63 00 68 00 65 00 63 00 6b 00 5c 00 [0-64] 2e 00 64 00 6c 00 6c 00 2c 00 76 00 65 00 72 00 69 00 66 00 79 00 6d 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

