rule TrojanDownloader_Win32_XWorm_CBV_2147851145_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/XWorm.CBV!MTB"
        threat_id = "2147851145"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "XWorm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c7 45 cc 6b 65 72 6e c7 45 d0 65 6c 33 32 c7 45 d4 2e 64 6c 6c c6 45 d8 00 ff}  //weight: 1, accuracy: High
        $x_1_2 = {c7 45 bc 56 69 72 74 c7 45 c0 75 61 6c 41 c7 45 c4 6c 6c 6f 63 c6 45 c8 00 ff}  //weight: 1, accuracy: High
        $x_1_3 = {c7 45 dc 68 74 74 70 c7 45 e0 73 3a 2f 2f c7 45 e4 70 61 73 74 c7 45 e8 65 2e 65 65 c7 45 ec 2f 72 2f 59 c7 45 f0 36 72 6b 66 c7 45}  //weight: 1, accuracy: High
        $x_1_4 = "https://paste.ee/r/Y6rkf" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

