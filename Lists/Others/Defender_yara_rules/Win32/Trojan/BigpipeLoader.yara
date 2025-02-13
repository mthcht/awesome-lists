rule Trojan_Win32_BigpipeLoader_MA_2147835131_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BigpipeLoader.MA!MTB"
        threat_id = "2147835131"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BigpipeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {c7 44 24 10 00 00 00 00 8d 85 c8 f9 ff ff 89 44 24 0c c7 44 24 08 ?? ?? ?? ?? 8b 45 f0 89 44 24 04 8b 45 ec 89 04 24 a1 ?? ?? ?? ?? ff d0 83 ec 14 85 c0 74}  //weight: 10, accuracy: Low
        $x_1_2 = "CryptDecrypt" ascii //weight: 1
        $x_1_3 = "NtQueryInformationProcess" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BigpipeLoader_MB_2147835133_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BigpipeLoader.MB!MTB"
        threat_id = "2147835133"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BigpipeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {33 c5 89 45 fc 53 8b 5d 0c 33 c0 56 8b 75 08 57 50 68 80 00 00 00 6a 03 50 6a 07 68 00 00 00 80 68 ?? ?? ?? ?? 89 03 ff 15}  //weight: 10, accuracy: Low
        $x_10_2 = {8b 45 f8 8b 4d f4 01 06 2b c8 01 03 89 4d f4 85 c9 75 d9}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

