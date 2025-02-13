rule TrojanDownloader_Win64_Vityce_B_2147719485_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/Vityce.B!bit"
        threat_id = "2147719485"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "Vityce"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "ddyv8sl7ewq1w.cloudfront.net/i1/r1.php" wide //weight: 2
        $x_1_2 = "Global\\FastPrintServices" wide //weight: 1
        $x_1_3 = "SOFTWARE\\Microsoft\\Fast Print Services" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

