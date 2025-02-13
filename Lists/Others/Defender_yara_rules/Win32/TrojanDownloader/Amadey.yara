rule TrojanDownloader_Win32_Amadey_GUC_2147833541_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Amadey.GUC!MTB"
        threat_id = "2147833541"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {0f 43 ca 03 c1 3b f0 74 5d 8a 04 33 32 06 8b 57 10 8b 5f 14 88 45 ec 3b d3 73 28 8d 4a 01 89 4f 10 8b cf 83 fb 10 72}  //weight: 10, accuracy: High
        $x_1_2 = "Amadey\\Release\\Amadey.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Amadey_GDS_2147839868_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Amadey.GDS!MTB"
        threat_id = "2147839868"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f 43 ca 03 c1 3b f0 74 59 8b 45 e0 8b 57 10 8a 0c 30 32 0e 88 4d f0 3b 57 14 73 26 83 7f 14 10 8d 42 01 89 47 10 8b c7 72 ?? 8b 07 88 0c 10 46 c6 44 10 01 00 a1 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? eb}  //weight: 10, accuracy: Low
        $x_1_2 = "Amadey\\Release\\Amadey.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Amadey_PACJ_2147898117_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Amadey.PACJ!MTB"
        threat_id = "2147898117"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c1 99 6a 28 5e f7 fe 8a 82 ?? ?? ?? ?? 32 81 ?? ?? ?? ?? 8b 54 24 10 88 04 11 41 3b 4c 24 14 72 de}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Amadey_PACK_2147898118_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Amadey.PACK!MTB"
        threat_id = "2147898118"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d2 32 cb 23 d2 d0 c1 f6 d1 66 c1 ea ec 13 d2 8d 94 d2 ?? ?? ?? ?? fe c1 52 80 f1 03 80 c2 86 32 d9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Amadey_PACQ_2147898823_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Amadey.PACQ!MTB"
        threat_id = "2147898823"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 44 0c 10 04 73 88 84 0c a8 00 00 00 41 83 f9 09 7c ed}  //weight: 1, accuracy: High
        $x_1_2 = {8a 44 0c 2c 34 8a 88 84 0c f0 00 00 00 41 3b ca 7c ee}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

