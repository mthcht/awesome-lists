rule TrojanDownloader_Win32_Nistio_A_2147647734_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Nistio.A"
        threat_id = "2147647734"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Nistio"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 65 78 65 00 67 65 74 00 32 30 30 30 00 fd 9a 80 5c 45 78 65 63 50 72 69 2e 64 6c 6c 00 68 69 67 68 00 45 78 65 63 57 61 69 74 00 fd ?? 80}  //weight: 1, accuracy: Low
        $x_1_2 = {31 30 33 34 00 31 30 33 39 00 31 30 32 38 00 31 32 35 36 00 ff ?? 80 20 00 [0-15] fd ?? 80 5c 69 6e 65 74 63 2e 64 6c 6c 00 2f 65 6e 64 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

