rule TrojanDownloader_Win32_Mecifg_A_2147661904_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Mecifg.A"
        threat_id = "2147661904"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Mecifg"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "os=%s&st=%lu&ok=%lu" ascii //weight: 1
        $x_1_2 = {51 50 ff 75 ?? ff 55 ?? 57 ff 75 ?? ff 55 ?? ff 75 ?? ff 15 ?? ?? ?? ?? ff 75 ?? ff 15 ?? ?? ?? ?? e9 ?? ?? 00 00 6a 40 68 00 10 10 00 8d 83 ?? 08 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

