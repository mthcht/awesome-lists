rule TrojanDownloader_Win32_Shelm_A_2147889000_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Shelm.A!MTB"
        threat_id = "2147889000"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Shelm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {30 40 00 c7 44 24 18 00 00 00 00 c7 44 24 14 00 00 00 00 c7 44 24 10 00 00 00 00 c7 44 24 0c 00 00 00 00 c7 44 24 08 10 00 00 00 c7 44 24 04 24 30 40 00 89 04 24 a1}  //weight: 2, accuracy: High
        $x_2_2 = {83 ec 18 a3 ?? 30 40 00 66 c7 05 ?? 30 40 00 02 00 0f b7 45 f2 0f b7 c0 89 04 24 a1 ?? ?? 40 00 ff d0 83 ec 04 66 a3 ?? 30 40 00 8b 45 f4 89 04 24 a1}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Shelm_B_2147889417_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Shelm.B!MTB"
        threat_id = "2147889417"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Shelm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {89 c2 89 c1 83 c5 ?? d1 ea 89 d0 f7 e3 c1 ea ?? 6b d2 ?? 29 d1 0f b6 81}  //weight: 2, accuracy: Low
        $x_2_2 = "Mozilla/4" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Shelm_D_2147895683_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Shelm.D!MTB"
        threat_id = "2147895683"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Shelm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {83 ec 04 8d 85 ?? fa ff ff 89 44 24 04 c7 04 24 02 02 00 00 a1 ?? ?? 40 00 ff d0 83 ec 08 c7 44 24 14 00 00 00 00 c7 44 24 10 00 00 00 00 c7 44 24 0c 00 00 00 00 c7 44 24 08 06 00 00 00 c7 44 24 04 01 00 00 00 c7 04 24 02 00 00 00 a1 ?? ?? 40 00 ff d0 83 ec 18 89 45 ?? 66 c7 45}  //weight: 2, accuracy: Low
        $x_2_2 = {89 04 24 a1 ?? ?? 40 00 ff d0 83 ec 04 89 45 ?? 8b 45 0c 0f b7 c0 89 04 24 a1 ?? ?? 40 00 ff d0 83 ec 04 66 89 45 ?? c7 44 24 18 00 00 00 00 c7 44 24 14 00 00 00 00 c7 44 24 10 00 00 00 00 c7 44 24 0c 00 00 00 00 c7 44 24 08 10 00 00 00 8d 45 ?? 89 44 24 04 8b 45 ?? 89 04 24 a1}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

