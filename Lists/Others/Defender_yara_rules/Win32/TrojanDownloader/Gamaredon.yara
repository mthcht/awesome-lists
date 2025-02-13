rule TrojanDownloader_Win32_Gamaredon_SK_2147837882_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Gamaredon.SK!MTB"
        threat_id = "2147837882"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Gamaredon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 69 64 63 6f 6e 3a 63 6d 64 2e 65 78 65 20 2f 63 20 65 63 68 6f 20 27 [0-9] 2e 69 63 6f 3e 3e 20 25 41 50 50 44 41 54 41 25 5c 5c [0-9] 2e 69 63 6f 2e 74 6d 70 2e 76 62 73}  //weight: 1, accuracy: Low
        $x_1_2 = {22 68 69 64 63 6f 6e 3a 63 6d 64 2e 65 78 65 20 2f 63 20 73 74 61 72 74 20 2f 62 20 25 41 50 50 44 41 54 41 25 5c 5c [0-9] 2e 69 63 6f 2e 74 6d 70 2e 76 62 73 22}  //weight: 1, accuracy: Low
        $x_1_3 = {52 75 6e 50 72 6f 67 72 61 6d 3d 22 68 69 64 63 6f 6e 3a 63 6d 64 2e 65 78 65 20 2f 63 20 65 63 68 6f 20 24 3e 20 25 41 50 50 44 41 54 41 25 5c 5c [0-9] 2e 69 63 6f 2e 74 6d 70 2e 76 62 73 22}  //weight: 1, accuracy: Low
        $x_1_4 = "SelfDelete=\"1\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Gamaredon_SL_2147902960_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Gamaredon.SL!MTB"
        threat_id = "2147902960"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Gamaredon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 69 64 63 6f 6e 3a 63 6d 64 2e 65 78 65 20 2f 63 20 63 6f 70 79 20 2f 79 20 25 54 45 4d 50 25 5c [0-9] 2e 6d 6f 76 20 25 41 50 50 44 41 54 41 25 5c [0-9] 2e 6d 6f 76 2e 74 6d 70}  //weight: 1, accuracy: Low
        $x_1_2 = {68 69 64 63 6f 6e 3a 63 6d 64 2e 65 78 65 20 2f 63 20 64 65 6c 20 2f 66 20 2f 71 20 25 41 50 50 44 41 54 41 25 5c [0-9] 2e 6d 6f 76 2e 74 6d 70}  //weight: 1, accuracy: Low
        $x_1_3 = {22 68 69 64 63 6f 6e 3a 63 6d 64 2e 65 78 65 20 2f 63 20 73 74 61 72 74 20 2f 62 20 25 41 50 50 44 41 54 41 25 5c [0-9] 2e 6d 6f 76 2e 76 62 73 22}  //weight: 1, accuracy: Low
        $x_1_4 = "SelfDelete=\"1\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

