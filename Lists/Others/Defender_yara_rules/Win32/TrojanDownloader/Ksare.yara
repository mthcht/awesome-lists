rule TrojanDownloader_Win32_Ksare_A_2147618606_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Ksare.A"
        threat_id = "2147618606"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Ksare"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "delete HKLM\\SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Minimal\\{4D36E967-E325-11CE-BFC1-08002BE10318} /F" ascii //weight: 1
        $x_1_2 = "ZwOpenSection" ascii //weight: 1
        $x_1_3 = "%H%M%S" ascii //weight: 1
        $x_1_4 = {50 56 8d 85 ?? ?? ?? ?? 50 68 e8 03 00 00 ff 35 ?? ?? ?? ?? 89 ?? ?? ?? ?? ?? ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

