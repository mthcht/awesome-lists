rule TrojanDownloader_Win32_Jinim_A_2147692706_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Jinim.A"
        threat_id = "2147692706"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Jinim"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff ff 0f be 82 ?? ?? ?? ?? 33 c9 8a 0d ?? ?? ?? ?? 33 c1 8b 95 ec fc ff ff 88 82 ?? ?? ?? ?? eb 9c}  //weight: 1, accuracy: Low
        $x_1_2 = {2f 4d 69 6e 69 4a 53 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 25 73 3b 6e 65 77 20 44 6f 77 6e 6c 6f 61 64 65 72 28 27 25 73 27 2c 20 27 25 73 27 29 2e 46 69 72 65 28 29 3b 00}  //weight: 1, accuracy: High
        $x_1_4 = "rundll32.exe %s RealService %s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

