rule TrojanDownloader_Win32_Unjuz_A_2147649014_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Unjuz.A"
        threat_id = "2147649014"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Unjuz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "unzjs.com/test_config/" ascii //weight: 1
        $x_1_2 = "g.uue.cn/uu/" ascii //weight: 1
        $x_1_3 = "%.2d-%.2d-%.2d-%s=%.4d-%.2d-%.2d" ascii //weight: 1
        $x_3_4 = {89 45 b0 50 8d 45 f4 64 a3 00 00 00 00 89 8d 84 fb ff ff 8d 85 ac fb ff ff 50 6a 00 6a 00 6a 1a 6a 00 ff 15}  //weight: 3, accuracy: High
        $x_3_5 = {81 7d c4 2d 01 00 00 74 16 81 7d c4 2e 01 00 00 74 0d 81 7d c4 2f 01 00 00 0f 85 86 02 00 00 6a 00 8d 55 b8 52 6a 16 8b 4d cc}  //weight: 3, accuracy: High
        $x_3_6 = {8b 4d cc 8b 11 8b 4d cc 8b 42 4c ff d0 8b 4d cc 89 8d 88 fb ff ff 8b 95 88 fb ff ff 89 95 8c fb ff ff 83 bd 8c fb ff ff 00}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

