rule TrojanDownloader_Win32_Citeary_A_2147893143_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Citeary.A!MTB"
        threat_id = "2147893143"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Citeary"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {c6 45 f0 6b c6 45 f1 65 c6 45 f2 72 c6 45 f3 6e c6 45 f4 65 c6 45 f5 6c c6 45 f6 33 c6 45 f7 32 c6 45 f8 2e c6 45 f9 64 c6 45 fa 6c c6 45 fb 6c}  //weight: 2, accuracy: High
        $x_2_2 = {c6 45 ec 48 c6 45 ed 65 c6 45 ee 61 c6 45 ef 70 c6 45 f0 46 c6 45 f1 72 c6 45 f2 65 c6 45 f3 65}  //weight: 2, accuracy: High
        $x_2_3 = {c6 45 b0 48 c6 45 b1 65 c6 45 b2 61 c6 45 b3 70 c6 45 b4 41 c6 45 b5 6c c6 45 b6 6c c6 45 b7 6f c6 45 b8 63}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

