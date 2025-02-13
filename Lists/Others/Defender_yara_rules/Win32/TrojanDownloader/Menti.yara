rule TrojanDownloader_Win32_Menti_B_2147658641_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Menti.B"
        threat_id = "2147658641"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Menti"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "job.exe" ascii //weight: 1
        $x_1_2 = "hob.exe" ascii //weight: 1
        $x_1_3 = "iob.exe" ascii //weight: 1
        $x_1_4 = "gob.exe" ascii //weight: 1
        $x_1_5 = {8b c8 c1 e9 0a 81 e9 00 28 00 00 25 ff 03 00 00 2d 00 24 00 00 66 89 0c 57 66 89 44 57 02 42 42 8b 4d fc 3b 4d 10 0f 85 4c ff ff ff 33 c0 40 8b 4d 08 5e 89 11 5b c9}  //weight: 1, accuracy: High
        $x_1_6 = {8b 02 8b 0e 8a 0c 08 8a c1 e8 ?? ?? ?? ?? 84 c0 75 10 80 f9 3b 75 17 8b c6 e8 ?? ?? ?? ?? 84 c0 74 09 ff 06 8b 06 3b 42 04 7c d5}  //weight: 1, accuracy: Low
        $x_1_7 = {59 be f9 93 04 00 33 db 53 53}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

