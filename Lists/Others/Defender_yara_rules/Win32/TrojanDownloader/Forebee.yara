rule TrojanDownloader_Win32_Forebee_A_2147610326_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Forebee.A"
        threat_id = "2147610326"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Forebee"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {7e 14 8b 4c 24 04 53 8a 1c 08 80 f3 ?? 88 1c 08 40 3b c2 7c f2}  //weight: 1, accuracy: Low
        $x_1_2 = {83 c1 4b 89 0d ?? ?? 40 00 8b ce e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

