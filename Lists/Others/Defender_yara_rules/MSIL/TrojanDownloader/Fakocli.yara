rule TrojanDownloader_MSIL_Fakocli_A_2147692191_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Fakocli.A"
        threat_id = "2147692191"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Fakocli"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "http://rcleaner.us/" wide //weight: 1
        $x_1_2 = {5c 00 52 00 43 00 6c 00 65 00 61 00 6e 00 65 00 72 00 2e 00 65 00 78 00 65 00 ?? ?? 53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 ?? ?? 57 00 49 00 4e 00 ?? ?? 57 00 49 00 4e 00 31 00 ?? ?? 5c 00 ?? ?? 57 00 49 00 4e 00 32 00 ?? ?? 57 00 49 00 4e 00 33 00 ?? ?? 53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 52 00 65 00 67 00 69 00 73 00 74 00 72 00 79 00 20 00 43 00 6c 00 65 00 61 00 6e 00 65 00 72 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

