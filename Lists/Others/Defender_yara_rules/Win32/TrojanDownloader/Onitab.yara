rule TrojanDownloader_Win32_Onitab_A_2147658625_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Onitab.A"
        threat_id = "2147658625"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Onitab"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "%02X-%02X-%02X-%02X-%02X-%02X" ascii //weight: 2
        $x_2_2 = "\\Debugs.inf" ascii //weight: 2
        $x_2_3 = "!@#$r#@%@#$@#" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

