rule Trojan_Win32_Copim_A_2147659456_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copim.A"
        threat_id = "2147659456"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copim"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {b9 5e ff ff ff 81 e9 53 ff ff ff f7 f1 89 45 f4 8b 55 0c 03 55 f4 8a 02 88 45 f3 8b ff 8b 4d 08 03 4d f4 8a 55 f3 88 11 8b 45 fc 83 c0 04 83 c0 07 89 45 fc}  //weight: 10, accuracy: High
        $x_5_2 = {5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 50 6f 6c 69 63 69 65 73 5c 53 79 73 74 65 6d 00 00 00 45 6e 61 62 6c 65 4c 55 41}  //weight: 5, accuracy: High
        $x_1_3 = "Elevation:Administrator!new:" wide //weight: 1
        $x_1_4 = "CopierMircosoft" ascii //weight: 1
        $x_1_5 = "VBoxService.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

