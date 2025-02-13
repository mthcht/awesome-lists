rule TrojanDownloader_Win32_Momole_2147723614_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Momole"
        threat_id = "2147723614"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Momole"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b8 7a f1 02 00 3b f0 7f 2e 6a 00 8b c6 03 c3 0f 80 9e 00 00 00 50 53 6a 03 8d 45 d0 50 6a 04 57 e8 ef 33 f9 ff 83 c4 1c 6a 01 58 03 c6 0f 80 80 00 00 00 8b f0 eb c9}  //weight: 1, accuracy: High
        $x_1_2 = {02 47 02 66 0f fc ea 0f f8 c4 0f ec eb ff e0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

