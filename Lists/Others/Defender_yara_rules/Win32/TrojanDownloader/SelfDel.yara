rule TrojanDownloader_Win32_SelfDel_AP_2147830929_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/SelfDel.AP!MTB"
        threat_id = "2147830929"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "SelfDel"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "kmmschool.org/wp-content/aa%d.exe" wide //weight: 2
        $x_2_2 = "8olp876l867l" wide //weight: 2
        $x_2_3 = "kmmschool.org/wp-content/aa%d.php" wide //weight: 2
        $x_1_4 = "InternetCrackUrlW" ascii //weight: 1
        $x_1_5 = "WriteFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

