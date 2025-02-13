rule TrojanDownloader_Win32_PSWebtoos_A_2147807501_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/PSWebtoos.A"
        threat_id = "2147807501"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "PSWebtoos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "32"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "powershell" ascii //weight: 10
        $x_10_2 = "http" ascii //weight: 10
        $x_10_3 = "net-webclient" ascii //weight: 10
        $x_1_4 = "downloadstring" ascii //weight: 1
        $x_1_5 = "downloadfile" ascii //weight: 1
        $x_1_6 = "start-process" ascii //weight: 1
        $x_1_7 = "iex" wide //weight: 1
        $x_1_8 = "invoke-expression" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

