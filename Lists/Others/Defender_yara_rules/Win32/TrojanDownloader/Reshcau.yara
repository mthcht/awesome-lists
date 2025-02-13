rule TrojanDownloader_Win32_Reshcau_A_2147630306_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Reshcau.A"
        threat_id = "2147630306"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Reshcau"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3c 6f 74 08 3c 75 0f 85}  //weight: 1, accuracy: High
        $x_1_2 = {46 6a 00 6a 01 8d 45 ef 50 53 e8 ?? ?? ?? ?? 85 c0 7f e3}  //weight: 1, accuracy: Low
        $x_1_3 = {b8 1d 00 00 00 e8 ?? ?? ?? ?? 40 ba ?? ?? ?? ?? 8a 44 02 ff 88 03 43 4e 75 e6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

