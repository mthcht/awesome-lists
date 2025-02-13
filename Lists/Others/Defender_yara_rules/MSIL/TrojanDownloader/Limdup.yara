rule TrojanDownloader_MSIL_Limdup_A_2147682446_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Limdup.A"
        threat_id = "2147682446"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Limdup"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 3a 5c 55 73 65 72 73 5c 4c 49 4d 41 5c 44 65 73 6b 74 6f 70 5c 31 5c 41 70 70 6c 69 63 61 74 69 6f 6e 31 2e 30 [0-5] 55 70 64 61 74 65 [0-5] 55 70 64 61 74 65 [0-5] 55 70 64 61 74 65 5c 6f 62 6a 5c 78 38 36 5c 52 65 6c 65 61 73 65 5c [0-10] 55 70 64 61 74 65 2e 70 64 62}  //weight: 1, accuracy: Low
        $x_1_2 = {20 98 3a 00 00 28 ?? 00 00 0a 28 ?? 00 00 0a ?? ?? ?? ?? ?? 28 ?? 00 00 0a 28 ?? 00 00 0a 26 2a}  //weight: 1, accuracy: Low
        $x_1_3 = {55 00 70 00 64 00 61 00 74 00 65 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 60 00 2e 00 65 00 78 00 65 00 40 00 2f 00 69 00 6d 00 61 00 67 00 65 00 73 00 2f 00 ?? ?? 2f 00}  //weight: 1, accuracy: Low
        $x_1_4 = {55 70 64 61 74 65 2e 65 78 65 00 [0-5] 57 00 69 00 6e 00 46 00 6f 00 72 00 6d 00 73 00 5f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

