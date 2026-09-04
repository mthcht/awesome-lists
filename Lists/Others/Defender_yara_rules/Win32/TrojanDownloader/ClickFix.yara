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
        $x_1_10 = "[scriptblock]::create" wide //weight: 1
        $x_1_11 = "iex" wide //weight: 1
        $x_1_12 = "invoke-expression" wide //weight: 1
        $x_1_13 = "start-process" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_100_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

