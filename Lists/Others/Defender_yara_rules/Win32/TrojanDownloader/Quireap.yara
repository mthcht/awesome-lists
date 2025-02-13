rule TrojanDownloader_Win32_Quireap_A_2147705496_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Quireap.A"
        threat_id = "2147705496"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Quireap"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {2f 6c 61 75 6e 63 68 5f 72 65 62 2e 70 68 70 3f 70 3d 73 65 76 65 6e 7a 69 70 [0-16] 26 74 69 64 3d}  //weight: 4, accuracy: Low
        $x_2_2 = "download_quiet" ascii //weight: 2
        $x_2_3 = "User-Agent: NSISDL/1.2 (Mozilla)" ascii //weight: 2
        $x_1_4 = "Optimize" ascii //weight: 1
        $x_1_5 = "\\setup.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

