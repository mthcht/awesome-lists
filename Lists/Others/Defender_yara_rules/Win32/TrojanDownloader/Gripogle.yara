rule TrojanDownloader_Win32_Gripogle_A_2147767489_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Gripogle.A"
        threat_id = "2147767489"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Gripogle"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = " certreq " wide //weight: 1
        $x_1_2 = " certreq.exe " wide //weight: 1
        $x_1_3 = " -post " wide //weight: 1
        $x_1_4 = " -config " wide //weight: 1
        $x_2_5 = "//iplogger.org/" wide //weight: 2
        $x_1_6 = "/1dH487" wide //weight: 1
        $x_1_7 = "/1OfpJ" wide //weight: 1
        $x_1_8 = "1MzDN6" wide //weight: 1
        $x_1_9 = "1u8qi7" wide //weight: 1
        $x_1_10 = "1qB8i7" wide //weight: 1
        $x_1_11 = "1pnPe7" wide //weight: 1
        $x_1_12 = "1pzPe7" wide //weight: 1
        $x_1_13 = "1Spuu7" wide //weight: 1
        $n_100_14 = "msedgewebview2.exe" wide //weight: -100
        $n_1000_15 = "if false == false echo" wide //weight: -1000
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Gripogle_B_2147767490_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Gripogle.B"
        threat_id = "2147767490"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Gripogle"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "start-bitstransfer " wide //weight: 1
        $x_3_2 = {20 00 2d 00 73 00 6f 00 75 00 72 00 63 00 65 00 20 00 [0-8] 68 00 74 00 74 00 70 00 [0-16] 69 00 70 00 6c 00 6f 00 67 00 67 00 65 00 72 00 2e 00 6f 00 72 00 67 00}  //weight: 3, accuracy: Low
        $x_1_3 = "/1dH487" wide //weight: 1
        $x_1_4 = "/1OfpJ" wide //weight: 1
        $x_1_5 = "/1MzDN6" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Gripogle_AS_2147769440_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Gripogle.AS"
        threat_id = "2147769440"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Gripogle"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "\\windows\\system32\\cmd.exe" wide //weight: 10
        $x_3_2 = {73 00 74 00 61 00 72 00 74 00 20 00 [0-8] 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 69 00 70 00 6c 00 6f 00 67 00 67 00 65 00 72 00 2e 00 6f 00 72 00 67 00 2f 00}  //weight: 3, accuracy: Low
        $x_3_3 = {73 00 74 00 61 00 72 00 74 00 20 00 [0-8] 68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 69 00 70 00 6c 00 6f 00 67 00 67 00 65 00 72 00 2e 00 6f 00 72 00 67 00 2f 00}  //weight: 3, accuracy: Low
        $x_1_4 = "/1dH487" wide //weight: 1
        $x_1_5 = "/1OfpJ" wide //weight: 1
        $x_1_6 = "1MzDN6" wide //weight: 1
        $x_1_7 = "1u8qi7" wide //weight: 1
        $x_1_8 = "1qB8i7" wide //weight: 1
        $x_1_9 = "1pnPe7" wide //weight: 1
        $x_1_10 = "1pzPe7" wide //weight: 1
        $x_1_11 = "1Spuu7" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*) and 7 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_3_*))) or
            (all of ($x*))
        )
}

