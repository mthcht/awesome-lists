rule TrojanDownloader_Win32_Delevid_A_2147607494_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delevid.A"
        threat_id = "2147607494"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delevid"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 fc 8b 55 f8 8a 5c 10 ff 80 c3 ?? 8d 45 f4 8b d3 e8 ?? ?? ff ff 8b 55 f4 8b c7 e8 ?? ?? ff ff ff 45 f8 4e 75 d9}  //weight: 1, accuracy: Low
        $x_1_2 = {c6 44 18 05 6d 8d 45 fc e8 ?? ?? ff ff c6 44 18 06 33 8d 45 fc e8 ?? ?? ff ff c6 44 18 07 32}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

