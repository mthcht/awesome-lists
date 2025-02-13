rule TrojanDownloader_Win32_Gotokum_A_2147626486_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Gotokum.A"
        threat_id = "2147626486"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Gotokum"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2f 62 61 69 61 79 2e 74 78 74 00 00 39 31 36 32 00 00 00 00 64 61 68 2f 30 00 00 00 6d 2e 63 6e 2f 6b 73 00 2e 79 6f 75 6b 75 00 00 68 74 74 70 3a 2f 2f 39 30 37 36 35}  //weight: 1, accuracy: High
        $x_1_2 = {d3 a6 d3 c3 b3 cc d0 f2 cd f8 c2 e7 b7 c3 ce ca bc e0 bf d8}  //weight: 1, accuracy: High
        $x_1_3 = "liaase.exe" ascii //weight: 1
        $x_1_4 = {56 8b 74 24 08 68 ?? ?? 40 00 56 e8 d1 8d 00 00 68 ?? ?? 40 00 56 e8 d6 8d 00 00 68 ?? ?? 40 00 56 e8 cb 8d 00 00 68 ?? ?? 40 00 56 e8 c0 8d 00 00 68 ?? ?? 40 00 56 e8 b5 8d 00 00 68 ?? ?? 40 00 56 e8 aa 8d 00 00 83 c4 30}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

