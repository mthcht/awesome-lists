rule TrojanDownloader_Win32_Kirssao_A_2147693823_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Kirssao.A"
        threat_id = "2147693823"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Kirssao"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {c6 45 dd 61 c6 45 de 6f c6 45 df 33 c6 45 e0 36 c6 45 e1 30 c6 45 e2 79 c6 45 e3 6e c6 45 e4 69}  //weight: 2, accuracy: High
        $x_2_2 = {c1 e6 06 3c 3d 75 09 c7 45 fc 01 00 00 00 eb 11 50 e8}  //weight: 2, accuracy: High
        $x_1_3 = "t7Ozr+n8/O7x7v3z7v3u7+b97vLx/Li2sLD9t98=" ascii //weight: 1
        $x_1_4 = "3+3t7urv7+7v7+/f9/j3+N/3+Pf43/Dt7uvs6er38Orv7fjq34vw7O/u7/ffiq" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

