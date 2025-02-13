rule TrojanDownloader_Win32_Nivdort_A_2147893498_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Nivdort.A!MTB"
        threat_id = "2147893498"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Nivdort"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {f7 f3 8b 45 ?? 01 d0 0f b6 00 31 f0}  //weight: 2, accuracy: Low
        $x_2_2 = {8b 45 f4 ba ?? ?? ?? ?? f7 f1 8b 45 ?? 01 d0 0f b6 00 31 c3}  //weight: 2, accuracy: Low
        $x_2_3 = {f7 f3 0f b6 44 15 ?? 30 04 0e 83 c1}  //weight: 2, accuracy: Low
        $x_2_4 = {89 c8 31 d2 f7 f6 0f b6 44 15 ?? 30 04 0b 83 c1}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

