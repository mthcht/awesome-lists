rule TrojanDownloader_Win64_Brbank_A_2147725102_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/Brbank.A"
        threat_id = "2147725102"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "Brbank"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "itauaplicativo.exe" ascii //weight: 1
        $x_2_2 = {31 c0 49 39 c1 76 09 80 34 02 08 48 ff c0 eb}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

