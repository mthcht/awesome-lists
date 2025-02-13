rule TrojanDownloader_Win32_Syten_A_2147696770_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Syten.A"
        threat_id = "2147696770"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Syten"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {c6 45 e0 4d c6 45 e1 6f c6 45 e2 7a c6 45 e3 69 c6 45 e4 6c c6 45 e5 6c c6 45 e6 61}  //weight: 3, accuracy: High
        $x_2_2 = {8b 5c 24 18 66 81 3b 4d 5a 0f 85 ?? ?? ?? 55 ff d6 8b 7b 3c 03 fb 81 3f 50 45 00 00 0f 85 ?? ?? ?? ?? 55}  //weight: 2, accuracy: Low
        $x_3_3 = {c6 45 f5 41 c6 45 f6 70 c6 45 f7 70 c6 45 f8 50 c6 45 f9 61 c6 45 fa 74 c6 45 fb 63 c6 45 fc 68}  //weight: 3, accuracy: High
        $x_5_4 = "http://61.160.222.11:" ascii //weight: 5
        $x_5_5 = "tby9yMG67O3vAanIvq8Bvr7f8O3u6+zp6vff+O/479/47/jv3+vs6+nt9/j36iUXdnsMEt+L8Ozv6e3" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*))) or
            ((1 of ($x_5_*) and 1 of ($x_2_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

