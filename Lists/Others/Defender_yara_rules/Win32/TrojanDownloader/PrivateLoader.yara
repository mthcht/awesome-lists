rule TrojanDownloader_Win32_PrivateLoader_KKA_2147960606_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/PrivateLoader.KKA!MTB"
        threat_id = "2147960606"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "PrivateLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {8b 44 24 10 8b 4c 24 14 83 f0 ?? ?? ?? ?? ?? ?? ?? 33 ca 89 44 24 30 89 4c 24 34 c7 44 24 20 ?? ?? ?? ?? 89 54 24 24 c7 44 24 18 ?? ?? ?? ?? 89 54 24 1c c7 44 24 28 ?? ?? ?? ?? 89 54 24 2c 8b 54 24 18 8b 74 24 1c 8b 44 24 20 03 d0}  //weight: 20, accuracy: Low
        $x_10_2 = {13 f1 83 c2 01 89 54 24 40 83 d6 00 89 74 24 44 8b 44 24 28 8b 4c 24 2c 8b 54 24 30 8b 74 24 34 2b d0 89 54 24 38 1b f1}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

