rule TrojanDownloader_Win32_Buzy_SIB_2147811829_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Buzy.SIB!MTB"
        threat_id = "2147811829"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Buzy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "D4B669E1-CDD4-2208-7A42-A045F4609710" ascii //weight: 1
        $x_1_2 = {33 ff 8b 48 ?? 83 c8 ?? 85 f6 7e ?? 40 3b c1 7e ?? 33 c0 8a 54 05 ?? 30 94 3d ?? ?? ?? ?? 47 3b fe 7c ?? ff 75 ?? 8d 85 05 56 8b 35 ?? ?? ?? ?? 6a ?? 50 ff d6 33 ff 83 c4 10 39 7d ?? 7e ?? ff 35 ?? ?? ?? ?? 8d 85 05 68 ?? ?? ?? ?? 6a ?? 50 ff d3 ff 75 07 8b f8 8d 85 05 57 6a ?? 50 ff d6 83 c4 20 85 ff 7f}  //weight: 1, accuracy: Low
        $x_1_3 = {8b fa 83 c7 ?? 3b fb 7e ?? ff d6 6a ?? 99 59 f7 f9 83 c2 30 83 fa 39 7e ?? 83 fa 41 7c ?? 88 54 1d ?? 43 3b df 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

