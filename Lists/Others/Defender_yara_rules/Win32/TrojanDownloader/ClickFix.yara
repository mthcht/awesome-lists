rule TrojanDownloader_Win32_ClickFix_JC_2147973969_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/ClickFix.JC"
        threat_id = "2147973969"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "challenge.cloudflare.com" wide //weight: 1
        $x_1_2 = "iex(irm" wide //weight: 1
        $x_1_3 = "/?sid=" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_ClickFix_MS_2147977560_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/ClickFix.MS"
        threat_id = "2147977560"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "202"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "http" wide //weight: 100
        $x_100_2 = "bypass" wide //weight: 100
        $x_1_3 = "irm" wide //weight: 1
        $x_1_4 = "invoke-restmethod" wide //weight: 1
        $x_1_5 = "iwr" wide //weight: 1
        $x_1_6 = "invoke-webrequest" wide //weight: 1
        $x_1_7 = "downloadstring" wide //weight: 1
        $x_1_8 = "downloaddata" wide //weight: 1
        $x_1_9 = "curl" wide //weight: 1
        $x_1_10 = "mshta" wide //weight: 1
        $x_1_11 = "[scriptblock]::create" wide //weight: 1
        $x_1_12 = "iex" wide //weight: 1
        $x_1_13 = "invoke-expression" wide //weight: 1
        $x_1_14 = "start-process" wide //weight: 1
        $x_1_15 = "start-job" wide //weight: 1
        $x_1_16 = "5048177c-51f8-4cdb-9338-c55cde761abf" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_100_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_ClickFix_JX_2147978481_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/ClickFix.JX"
        threat_id = "2147978481"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {66 00 6f 00 72 00 20 00 2f 00 22 01 01 02 66 6b 20 00 23 02 02 01 25 2a 01 01 00 20 00 69 00 6e 00 20 00 28 00 27 00 77 00 68 00 65 00 72 00 65 00 20 00 23 20 20 0c 61 2d 7a 41 2d 5a 30 2d 39 2e 5f 2d 22 01 01 02 3f 2a 23 20 20 0e 61 2d 7a 41 2d 5a 30 2d 39 2e 5f 3f 2a 2d 27 00 29 00}  //weight: 4, accuracy: Low
        $x_1_2 = {3d 00 68 00 74 00 74 00 70 00 73 00 3a 00 23 ff ff 19 61 2d 7a 41 2d 5a 30 2d 39 20 21 22 25 26 27 28 29 2e 2f 3a 3d 3f 5f 2a 2d 7c 00 23 02 02 01 25 2a 01 01 00}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 00 68 00 74 00 74 00 70 00 73 00 3a 00 23 ff ff 19 61 2d 7a 41 2d 5a 30 2d 39 20 21 22 25 26 27 28 29 2e 2f 3a 3d 3f 5f 2a 2d 7c 00 20 00 23 02 02 01 25 2a 01 01 00}  //weight: 1, accuracy: Low
        $x_1_4 = {3d 00 68 00 74 00 74 00 70 00 73 00 3a 00 23 ff ff 19 61 2d 7a 41 2d 5a 30 2d 39 20 21 22 25 26 27 28 29 2e 2f 3a 3d 3f 5f 2a 2d 7c 00 23 80 80 12 61 2d 7a 41 2d 5a 30 2d 39 20 22 25 2e 2f 3a 5c 5f 2d 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_5 = {3d 00 68 00 74 00 74 00 70 00 73 00 3a 00 23 ff ff 19 61 2d 7a 41 2d 5a 30 2d 39 20 21 22 25 26 27 28 29 2e 2f 3a 3d 3f 5f 2a 2d 7c 00 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

