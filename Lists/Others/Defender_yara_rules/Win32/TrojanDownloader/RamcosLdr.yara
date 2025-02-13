rule TrojanDownloader_Win32_RamcosLdr_PA_2147918020_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/RamcosLdr.PA!MTB"
        threat_id = "2147918020"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "RamcosLdr"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "@Madcrypt@DecryptA" ascii //weight: 1
        $x_1_2 = "@Madcrypt@EncryptA" ascii //weight: 1
        $x_3_3 = {8b 45 c0 40 89 45 c0 8b 45 ?? 83 c0 04 89 45 ?? 8b 45 ?? 3b 45 ?? 73 ?? 8b 45 ?? 8b 00 03 45 ?? 8b 4d ?? 89 01 eb ?? 8b 45 ?? 8b 40 4c 03 45 ?? 89 45 ?? 8b 45 ?? 40}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

