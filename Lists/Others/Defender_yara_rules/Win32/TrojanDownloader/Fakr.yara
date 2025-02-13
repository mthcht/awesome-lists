rule TrojanDownloader_Win32_Fakr_A_2147647790_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Fakr.A"
        threat_id = "2147647790"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Fakr"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "livefloat.com" ascii //weight: 1
        $x_1_2 = ".zeroclear.net" ascii //weight: 1
        $x_5_3 = {2f 63 6f 75 6e 74 2f 69 6e 73 74 (61 6c 6c 5f 63 6f 75 6e 74 2e 70 68|2e 70 68)}  //weight: 5, accuracy: Low
        $x_4_4 = "&kind=" ascii //weight: 4
        $x_3_5 = {5c 41 52 50 43 61 63 68 65 39 00 5c 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 41 70 70 20 4d 61 6e 61 67 65 6d 65 6e 74}  //weight: 3, accuracy: Low
        $n_5_6 = "addendum\\sidebar\\" ascii //weight: -5
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

