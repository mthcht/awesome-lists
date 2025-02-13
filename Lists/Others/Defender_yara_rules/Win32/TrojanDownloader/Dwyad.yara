rule TrojanDownloader_Win32_Dwyad_A_2147716604_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Dwyad.A"
        threat_id = "2147716604"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Dwyad"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 ad de ad de 83 c4 20 8b ?? ?? 05 00 30 00 00 ff d0 c6 ?? ?? 01 e8 ?? ?? ?? ?? 8d 45 ?? e8}  //weight: 1, accuracy: Low
        $x_1_2 = {43 3a 5c 78 31 5c 75 72 6c 5c 44 6f 77 [0-16] 43 3a 5c 78 31 5c 75 72 6c 5c 6e 6c 6f}  //weight: 1, accuracy: Low
        $x_1_3 = "C:\\Dwy\\TE\\ALLUSERSPROFILE" ascii //weight: 1
        $x_1_4 = {3a 5a 6f 6e 65 2e 49 64 65 6e 74 69 66 69 65 72 00 00 00 00 ff ff ff ff ?? 00 00 00 [0-48] 68 74 74 70 3a 2f 2f [0-48] 2e 65 78 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

