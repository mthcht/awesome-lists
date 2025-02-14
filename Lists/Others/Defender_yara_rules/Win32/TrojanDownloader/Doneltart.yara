rule TrojanDownloader_Win32_Doneltart_2147625697_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Doneltart"
        threat_id = "2147625697"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Doneltart"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {64 ff 30 64 89 20 8b 03 01 01 01 c3 c5 c6 e8 ?? ?? ?? ?? 03 01 01 01 bb bd be 01 00 00 00 (eb ??|e9 ?? ?? ?? ??) (b0 ??|8b 45 fc 8a ?? ??) (e8|(??|?? ??|?? ?? ??|?? ?? ?? ??|?? ?? ?? ?? ??|?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??) 8b) 3c 3a 73 03 2c 2f c3 3c 5b 73 06 2c 40 04 0a eb 0c 3c 7b 73 06 2c 60 04 24 eb 02 33 c0 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

