rule TrojanDownloader_Win32_Tobor_A_2147643668_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Tobor.A"
        threat_id = "2147643668"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Tobor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 68 b8 0b 00 00 6a 64 51 c7 ?? ?? ?? 00 00 00 00 00 00 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {3a 5c 00 00 5c 00 00 00 2e 70 69 66}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

