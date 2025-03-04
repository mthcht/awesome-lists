rule TrojanDownloader_Win32_VXIDL_2147804050_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/VXIDL"
        threat_id = "2147804050"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "VXIDL"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 00 64 00 6f 00 67 00 2e 00 73 00 79 00 73 00 00 00 00 00 7a 00 63 00 6c 00 69 00 65 00 6e}  //weight: 1, accuracy: High
        $x_1_2 = {61 00 76 00 73 00 73 00 2e 00 65 00 78 00 65 00 00 00 6b 00 61 00 76 00 73 00 76 00 63 00 2e 00}  //weight: 1, accuracy: High
        $x_1_3 = {0f 20 c0 50 25 ff ff fe ff 0f 22 c0}  //weight: 1, accuracy: High
        $x_1_4 = {00 00 8b 55 10 66 81 3a 4d 5a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_VXIDL_2147804050_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/VXIDL"
        threat_id = "2147804050"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "VXIDL"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {26 69 64 3d 00 00 00 00 25 75 00 00 63 3a 00 00 53 65 44 65 62 75 67 50 72 69 76 69 6c 65 67 65 00 00 00 00 25 64 00 00 43 3a 5c}  //weight: 4, accuracy: High
        $x_4_2 = {64 6c 6c 00 53 8b 1d ?? ?? ?? ?? 56 57 8b 7c 24 10 57 33 f6 ff d3 85 c0 7e 0c 80 04 3e ?? 57 46 ff d3 3b f0 7c f4 5f 5e 5b c2 04 00 55 8b ec 81}  //weight: 4, accuracy: Low
        $x_4_3 = {8d bd 40 fe ff ff f3 ab 8d 45 f8 50 8d 85 40 fe ff ff 50 be 00 01 00 00 53 89 75 f8 e8}  //weight: 4, accuracy: High
        $x_4_4 = {bf 00 04 00 00 83 7d f8 05 0f 8d ?? 00 00 00 53 68 80 00 00 00 6a 04 53 6a 02 68 00 00 00 40 ff 32}  //weight: 4, accuracy: Low
        $x_3_5 = {00 00 00 7d 01 40 83 c0 ?? 3d ?? 00 00 00 7c}  //weight: 3, accuracy: Low
        $x_1_6 = "IsProcessorFeaturePresent" ascii //weight: 1
        $x_1_7 = "SeDebugPrivilege" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_4_*) and 1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((3 of ($x_4_*) and 1 of ($x_1_*))) or
            ((3 of ($x_4_*) and 1 of ($x_3_*))) or
            ((4 of ($x_4_*))) or
            (all of ($x*))
        )
}

