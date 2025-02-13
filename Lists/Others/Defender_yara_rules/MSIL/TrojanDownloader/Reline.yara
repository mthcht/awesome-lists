rule TrojanDownloader_MSIL_Reline_GM_2147758389_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Reline.GM!MTB"
        threat_id = "2147758389"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Reline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {73 0b 00 00 0a 0a 06 [0-64] 6f 0c 00 00 0a 06 [0-64] 6f 0c 00 00 0a 06 6f 0d 00 00 0a 0d 2b 34}  //weight: 1, accuracy: Low
        $x_1_2 = {12 03 28 0e 00 00 0a 0b 73 0f 00 00 0a 0c 08 07 28 04 00 00 06 6f 10 00 00 0a 08 16 6f 11 00 00 0a 08 16 6f 12 00 00 0a 08 28 13 00 00 0a 26 de 03}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Reline_SIB_2147787417_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Reline.SIB!MTB"
        threat_id = "2147787417"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Reline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {68 00 74 00 74 00 70 00 [0-5] 3a 00 2f 00 2f 00 69 00 63 00 68 00 61 00 6c 00 6c 00 73 00 6b 00 2e 00 62 00 65 00 67 00 65 00 74 00 2e 00 [0-8] 2f 00 72 00 65 00 77 00 6f 00 72 00 6b 00 [0-10] 2e 00 65 00 78 00 65 00}  //weight: 10, accuracy: Low
        $x_10_2 = {68 74 74 70 [0-5] 3a 2f 2f 69 63 68 61 6c 6c 73 6b 2e 62 65 67 65 74 2e [0-8] 2f 72 65 77 6f 72 6b [0-10] 2e 65 78 65}  //weight: 10, accuracy: Low
        $x_1_3 = {6b 00 61 00 6e 00 65 00 6b 00 69 00 5c [0-96] 5c 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 45 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 2e 00 70 00 64 00 62 00}  //weight: 1, accuracy: Low
        $x_1_4 = {6b 61 6e 65 6b 69 5c [0-96] 5c 57 69 6e 64 6f 77 73 45 78 70 6c 6f 72 65 72 2e 70 64 62}  //weight: 1, accuracy: Low
        $x_1_5 = "FetchFiles" ascii //weight: 1
        $x_1_6 = "Execute" ascii //weight: 1
        $x_1_7 = "DownloadData" ascii //weight: 1
        $x_1_8 = "ProcessVmCounters" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 4 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_MSIL_Reline_SIBA_2147798221_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Reline.SIBA!MTB"
        threat_id = "2147798221"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Reline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "62"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 63 00 64 00 6e 00 2e 00 64 00 69 00 73 00 63 00 6f 00 72 00 64 00 61 00 70 00 70 00 2e 00 63 00 6f 00 6d 00 2f 00 61 00 74 00 74 00 61 00 63 00 68 00 6d 00 65 00 6e 00 74 00 73 00 2f 00 [0-96] 2f 00 56 00 6f 00 64 00 6f 00 4b 00 61 00 6e 00 61 00 6c 00 46 00 6f 00 72 00 6d 00 73 00 2e 00 64 00 6c 00 6c 00}  //weight: 20, accuracy: Low
        $x_20_2 = {68 74 74 70 73 3a 2f 2f 63 64 6e 2e 64 69 73 63 6f 72 64 61 70 70 2e 63 6f 6d 2f 61 74 74 61 63 68 6d 65 6e 74 73 2f [0-96] 2f 56 6f 64 6f 4b 61 6e 61 6c 46 6f 72 6d 73 2e 64 6c 6c}  //weight: 20, accuracy: Low
        $x_20_3 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 63 00 64 00 6e 00 2e 00 64 00 69 00 73 00 63 00 6f 00 72 00 64 00 61 00 70 00 70 00 2e 00 63 00 6f 00 6d 00 2f 00 61 00 74 00 74 00 61 00 63 00 68 00 6d 00 65 00 6e 00 74 00 73 00 2f 00 [0-96] 2f 00 [0-16] 2e 00 65 00 78 00 65 00}  //weight: 20, accuracy: Low
        $x_20_4 = {68 74 74 70 73 3a 2f 2f 63 64 6e 2e 64 69 73 63 6f 72 64 61 70 70 2e 63 6f 6d 2f 61 74 74 61 63 68 6d 65 6e 74 73 2f [0-96] 2f [0-16] 2e 65 78 65}  //weight: 20, accuracy: Low
        $x_20_5 = {56 00 6f 00 64 00 6f 00 4b 00 61 00 6e 00 61 00 6c 00 46 00 6f 00 72 00 6d 00 73 00 2e 00 [0-16] 4b 00 61 00 6e 00 61 00 6c 00}  //weight: 20, accuracy: Low
        $x_20_6 = {56 6f 64 6f 4b 61 6e 61 6c 46 6f 72 6d 73 2e [0-16] 4b 61 6e 61 6c}  //weight: 20, accuracy: Low
        $x_1_7 = "DownloadData" ascii //weight: 1
        $x_1_8 = {59 00 61 00 6e 00 64 00 65 00 78 00 [0-16] 41 00 70 00 69 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_9 = {59 61 6e 64 65 78 [0-16] 41 70 69 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_10 = "NETSecure" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_20_*) and 2 of ($x_1_*))) or
            ((4 of ($x_20_*))) or
            (all of ($x*))
        )
}

