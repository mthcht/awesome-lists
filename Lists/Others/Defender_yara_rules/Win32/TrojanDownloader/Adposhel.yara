rule TrojanDownloader_Win32_Adposhel_A_2147726830_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Adposhel.A"
        threat_id = "2147726830"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Adposhel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 f1 29 f9 89 d7 8b 55 d8 69 c9 ?? ?? ?? ?? 32 03 0f b6 c0 0f b6 80 ?? ?? ?? ?? 31 c1 88 0b 43 39 d3 0f 82 ?? ?? ?? ?? 47}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b6 03 89 f1 29 d9 69 c9 ?? ?? ?? ?? 29 f9 0f b6 80 ?? ?? ?? ?? 31 c1 88 0b 43 39 d3 0f 82 ?? ?? ?? ?? e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Adposhel_I_2147730216_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Adposhel.I"
        threat_id = "2147730216"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Adposhel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "echo bitsadmin /complete" ascii //weight: 1
        $x_1_2 = "echo bitsadmin /cancel" ascii //weight: 1
        $x_2_3 = "echo start /b /min regsvr32.exe /s /n /i:" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

