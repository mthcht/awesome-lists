rule TrojanDownloader_Win32_Likpeh_A_2147650656_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Likpeh.A"
        threat_id = "2147650656"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Likpeh"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4b 49 4c 4c 8d 50 01 8a 08 40 3a cb 75 f9 2b c2 83 f8 03 76 20 8d 8c 24 ?? ?? 00 00 51 8d 94 24 ?? ?? 00 00 52 e8 ?? ?? ?? ?? 83 c4 08 85 c0 0f 85 ?? ?? ?? ?? 8d 84 24 ?? ?? 00 00 c7 84 24 ?? ?? 00 00 68 74 74 70}  //weight: 1, accuracy: Low
        $x_1_2 = {83 c4 14 51 e8 ?? ?? ?? ?? 83 c4 04 68 40 0d 03 00 e8 ?? ?? ?? ?? 83 c4 04 68 3f 0d 03 00 8b f0 6a 00 56 e8 ?? ?? ?? ?? 83 c4 0c}  //weight: 1, accuracy: Low
        $x_1_3 = "//%s%s?act%sor&v=1&a=%d&id=%s&hardid=%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

