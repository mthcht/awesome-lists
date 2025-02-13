rule TrojanDownloader_Win32_Agentsmall_I_2147804022_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agentsmall.I"
        threat_id = "2147804022"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agentsmall"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {81 f2 87 1b 01 14 66 8b 30 66 46 66 89 30 43 81 e2 72 73 35 0b 66 8b 10 66 42 66 89 10 46 40 81 f7 c4 f5 4a 2b 40 81 e6 aa e8 25 1a bb 76 53 40 00 3b d8 75 cb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

