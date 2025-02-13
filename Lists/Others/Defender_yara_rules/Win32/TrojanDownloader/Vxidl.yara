rule TrojanDownloader_Win32_Vxidl_C_2147611327_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Vxidl.gen!C"
        threat_id = "2147611327"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Vxidl"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 45 f0 50 68 05 00 00 20 53 ff 55 ?? 89 45 0d 00 c7 45 ?? 04 00 00 00 6a 00 8d 45 ?? 50}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

