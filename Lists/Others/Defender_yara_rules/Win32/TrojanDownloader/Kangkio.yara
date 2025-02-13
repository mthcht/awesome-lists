rule TrojanDownloader_Win32_Kangkio_A_2147610899_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Kangkio.A"
        threat_id = "2147610899"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Kangkio"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "http://%77%77%77%2E%6B%61%6E%67%6B%2E%63%6E/%61%33%2E%68%74%6D" ascii //weight: 1
        $x_1_2 = "fuckallshaall" ascii //weight: 1
        $x_1_3 = "w.kangk.cn/" ascii //weight: 1
        $x_2_4 = {b8 08 20 00 00 e8 ?? ?? 00 00 55 56 6a 01 6a 00 6a 00 68 44 30 40 00 68 3c 30 40 00 6a 00 ff 15 08 22 40 00 8b e8}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

