rule TrojanDownloader_Win32_Tapaoux_A_2147651156_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Tapaoux.A"
        threat_id = "2147651156"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Tapaoux"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {75 15 8b d7 47 81 fa 58 02 00 00 7f 0a 6a 64 ff 15 ?? ?? ?? ?? eb a9 8b 86}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

