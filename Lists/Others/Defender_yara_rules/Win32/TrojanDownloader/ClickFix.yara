rule TrojanDownloader_Win32_ClickFix_JC_2147973852_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/ClickFix.JC"
        threat_id = "2147973852"
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

