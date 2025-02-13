rule TrojanDownloader_Win32_Cypaux_C_2147624265_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Cypaux.C"
        threat_id = "2147624265"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Cypaux"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ldr/loadList.php?version=" wide //weight: 1
        $x_1_2 = "WindowsUpadte" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

