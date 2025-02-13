rule TrojanDownloader_MSIL_Loipaoc_A_2147686495_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Loipaoc.A"
        threat_id = "2147686495"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Loipaoc"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {57 65 62 43 6c 69 65 6e 74 00 44 6f 77 6e 6c 6f 61 64 46 69 6c 65 00}  //weight: 1, accuracy: High
        $x_1_2 = "NtSetInformationProcess" ascii //weight: 1
        $x_1_3 = "lpcil" wide //weight: 1
        $x_1_4 = {1f 1d 12 00 1a 28 ?? 00 00 06}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

