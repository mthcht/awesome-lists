rule TrojanDownloader_Win32_Loan_BG_2147820502_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Loan.BG!MTB"
        threat_id = "2147820502"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Loan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {2b 4c 24 14 8b c1 33 c9 85 c0 76 0d 80 b4 0c 30 02 00 00 99 41 3b c8 72 f3 ff 74 24 10 50 8d 84 24 [0-4] 6a 01 50 ff 15 [0-4] 01 44 24 24 56 55 8d 84 24 [0-4] 6a 01 50 ff d3 83 c4 20 eb}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

