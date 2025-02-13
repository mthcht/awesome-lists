rule TrojanDownloader_AutoIt_Banload_R_2147694727_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:AutoIt/Banload.R"
        threat_id = "2147694727"
        type = "TrojanDownloader"
        platform = "AutoIt: AutoIT scripts"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Q7HqS3elBsOkOsmkR7alQNHbRNClC" wide //weight: 1
        $x_1_2 = {83 ef 08 8b cf 8b 5d f0 d3 eb 8b cf b8 01 00 00 00 d3 e0 8b c8 8b 45 f0 99 f7 f9 89 55 f0 b9 00 01 00 00 8b c3 99 f7 f9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

