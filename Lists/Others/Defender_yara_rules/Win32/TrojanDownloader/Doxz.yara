rule TrojanDownloader_Win32_Doxz_A_2147596332_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Doxz.A"
        threat_id = "2147596332"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Doxz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://cupid.556677889900.com/" ascii //weight: 1
        $x_1_2 = "windoxz" ascii //weight: 1
        $x_1_3 = "cupid_quitevent" ascii //weight: 1
        $x_1_4 = "Software\\cupid" ascii //weight: 1
        $x_10_5 = ".php?aff_id=%AFFID&lunch_id=%LUNCHID" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

