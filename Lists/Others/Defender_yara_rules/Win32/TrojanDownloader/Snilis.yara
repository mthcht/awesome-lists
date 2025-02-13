rule TrojanDownloader_Win32_Snilis_A_2147626637_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Snilis.A"
        threat_id = "2147626637"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Snilis"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6c 58 ff fc 90 fc e0 6a ff fb 11 6c 54 ff 6c 58 ff fc a0 6c 54 ff f5 01 00 00 00 aa 71 54 ff 04 70 ff 67 4c ff 2b 00}  //weight: 1, accuracy: High
        $x_1_2 = {2a 31 68 ff 32 20 00 60 ff 5c ff 58 ff 54 ff 50 ff 4c ff 48 ff 44 ff 40 ff 3c ff 38 ff 34 ff 30 ff 2c ff 28 ff 24 ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Snilis_B_2147626960_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Snilis.B"
        threat_id = "2147626960"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Snilis"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "9cV3v9p8N8Q8L9ycA4JcCaB5mbCdQ8A9VdBaBdVb" wide //weight: 1
        $x_1_2 = "bucks" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Snilis_C_2147627439_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Snilis.C"
        threat_id = "2147627439"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Snilis"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 18 32 5d ?? ff 75 ?? ff 75 ?? e8 ?? ?? ?? ?? 88 18 c7 45 fc 0f 00 00 00 8b 45 ?? 83 c0 01 0f 80 c1 00 00 00 89 45 ?? c7 45 fc 10 00 00 00 e9 7e fd ff ff}  //weight: 1, accuracy: Low
        $x_1_2 = {c7 45 fc 05 00 00 00 33 c0 66 83 3d ?? ?? ?? ?? 02 0f 95 c0 f7 d8 66 89 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

