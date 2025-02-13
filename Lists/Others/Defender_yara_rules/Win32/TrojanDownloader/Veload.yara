rule TrojanDownloader_Win32_Veload_A_2147650191_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Veload.A"
        threat_id = "2147650191"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Veload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 4c 24 18 c6 84 24 3c 0a 00 00 04 e8 ?? ?? ?? ?? 89 5c 24 10 68 ?? ?? ?? ?? 8d 4c 24 30 c6 84 24 3c 0a 00 00 06 e8 ?? ?? ?? ?? c6 84 24 38 0a 00 00 07 8b 44 24 2c ba 08 00 00 00 50 66 89 54 24 78 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {2f 2f 69 74 65 6d [0-4] 76 65 72 73 69 6f 6e [0-4] 64 6f 77 6e 75 72 6c}  //weight: 1, accuracy: Low
        $x_1_3 = {43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e [0-4] 6e 6f 76 65 6c 61 64}  //weight: 1, accuracy: Low
        $x_1_4 = "count.asp?exec=%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

