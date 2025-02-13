rule TrojanDownloader_MSIL_REntS_SIBA_2147794728_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/REntS.SIBA!MTB"
        threat_id = "2147794728"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "REntS"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {25 1f 2e 1f 73 9d [0-96] 25 1f 2d 1f 65 9d [0-96] 25 1f 2c 1f 72 9d [0-96] 25 1f 2b 1f 75 9d [0-96] 25 1f 2a 1f 74 9d [0-96] 25 1f 29 1f 61 9d [0-96] 25 1f 28 1f 65 9d [0-96] 25 1f 27 1f 66 9d [0-96] 25 1f 26 1f 2f 9d [0-96] 25 1f 25 1f 73 9d [0-96] 25 1f 24 1f 77 9d [0-96] 25 1f 23 1f 65 9d [0-96] 25 1f 22 1f 6e 9d [0-96] 25 1f 21 1f 2d 9d [0-96] 25 1f 20 1f 63 9d [0-96] 25 1f 1f 1f 66 9d [0-96] 25 1f 1e 1f 2d 9d [0-96] 25 1f 1d 1f 6c 9d [0-96] 25 1f 1c 1f 6f 9d [0-96] 25 1f 1b 1f 6f 9d [0-96] 25 1f 1a 1f 70 9d [0-96] 25 1f 19 1f 72 9d [0-96] 25 1f 18 1f 65 9d [0-96] 25 1f 17 1f 76 9d [0-96] 25 1f 16 1f 69 9d [0-96] 25 1f 15 1f 6c 9d}  //weight: 1, accuracy: Low
        $x_1_2 = {25 1f 47 1f 6c 9d [0-96] 25 1f 46 1f 6f 9d [0-96] 25 1f 45 1f 6f 9d [0-96] 25 1f 44 1f 70 9d [0-96] 25 1f 43 1f 72 9d [0-96] 25 1f 42 1f 65 9d [0-96] 25 1f 41 1f 76 9d [0-96] 25 1f 40 1f 69 9d [0-96] 25 1f 3f 1f 6c 9d [0-96] 25 1f 3e 1f 2d 9d [0-96] 25 1f 3d 1f 64 9d [0-96] 25 1f 3c 1f 72 9d [0-96] 25 1f 3b 1f 61 9d [0-96] 25 1f 3a 1f 72 9d [0-96] 25 1f 39 1f 72 9d [0-96] 25 1f 38 1f 65 9d [0-96] 25 1f 37 1f 67 9d [0-96] 25 1f 36 1f 2d 9d [0-96] 25 1f 35 1f 6e 9d [0-96] 25 1f 34 1f 65 9d [0-96] 25 1f 33 1f 76 9d [0-96] 25 1f 32 1f 65 9d [0-96] 25 1f 31 1f 74 9d [0-96] 25 1f 30 1f 73 9d}  //weight: 1, accuracy: Low
        $x_1_3 = {25 20 83 00 00 00 1f 6c 9d [0-96] 25 20 82 00 00 00 1f 6d 9d [0-96] 25 20 81 00 00 00 1f 74 9d [0-96] 25 20 80 00 00 00 1f 68 9d [0-96] 25 1f 7f 1f 2e 9d 50 05 25 1f 5d 1f 6c 9d [0-96] 25 1f 5c 1f 61 9d [0-96] 25 1f 5b 1f 6f 9d [0-96] 25 1f 5a 1f 67 9d [0-96] 25 1f 59 1f 2d 9d [0-96] 25 1f 58 1f 2d 9d [0-96] 25 1f 57 1f 68 9d [0-96] 25 1f 56 1f 73 9d [0-96] 25 1f 55 1f 69 9d [0-96] 25 1f 54 1f 6c 9d [0-96] 25 1f 53 1f 67 9d [0-96] 25 1f 52 1f 6c 9d [0-96] 25 1f 51 1f 61 9d [0-96] 25 1f 50 1f 64 9d [0-96] 25 1f 4f 1f 2d 9d [0-96] 25 1f 4e 1f 65 9d [0-96] 25 1f 4d 1f 72 9d [0-96] 25 1f 4c 1f 75 9d [0-96] 25 1f 4b 1f 74 9d [0-96] 25 1f 4a 1f 75 9d [0-96] 25 1f 49 1f 66 9d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_REntS_SIBB_2147798219_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/REntS.SIBB!MTB"
        threat_id = "2147798219"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "REntS"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {1f 2f 9d 25 [0-64] 25 1f ?? 1f 73 9d [0-64] 25 1f ?? 1f 77 9d [0-64] 25 1f ?? 1f 65 9d [0-64] 25 1f ?? 1f 6e 9d [0-64] 25 1f ?? 1f 2d 9d [0-64] 25 1f ?? 1f 63 9d [0-64] 25 1f ?? 1f 66 9d [0-64] 25 1f ?? 1f 2d 9d 25 [0-64] 25 1f ?? 1f 6c 9d [0-64] 25 1f ?? 1f 6f 9d [0-64] 25 1f ?? 1f 6f 9d [0-64] 25 1f ?? 1f 70 9d [0-64] 25 1f ?? 1f 72 9d [0-64] 25 1f ?? 1f 65 9d [0-64] 25 1f ?? 1f 76 9d [0-64] 25 1f ?? 1f 69 9d [0-64] 25 1f ?? 1f 6c 9d [0-64] 25 1f ?? 1f 2f 9d [0-64] 25 1f ?? 1f 71 9d [0-64] 25 1f ?? 1f 67 9d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

