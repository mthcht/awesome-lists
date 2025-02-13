rule TrojanDownloader_Win32_Svelta_A_2147627560_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Svelta.A"
        threat_id = "2147627560"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Svelta"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 7c 24 40 00 75 1c 8b c6 38 9c 24 d2 00 00 00 75 07 68 ?? ?? ?? 00 eb 05}  //weight: 1, accuracy: Low
        $x_1_2 = {73 74 61 74 75 73 65 73 2f 75 73 65 72 5f 74 69 6d 65 6c 69 6e 65 2f [0-10] 2e 72 73 73}  //weight: 1, accuracy: Low
        $x_1_3 = ".php?user=%s&name=%s&winver=%s&MAC=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

