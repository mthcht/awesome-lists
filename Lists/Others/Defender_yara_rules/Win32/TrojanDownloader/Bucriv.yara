rule TrojanDownloader_Win32_Bucriv_A_2147651000_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Bucriv.A"
        threat_id = "2147651000"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Bucriv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "1|%s|%d|%s|%s|%s|%s" ascii //weight: 1
        $x_1_2 = {04 53 0f 85 0b 00 80 (3e|3f) 41 0f 85 ?? ?? ?? ?? 80 (7e|7f)}  //weight: 1, accuracy: Low
        $x_1_3 = {56 68 00 00 00 80 56 56 8d 85 00 fe ff ff 50 57 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Bucriv_B_2147653967_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Bucriv.B"
        threat_id = "2147653967"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Bucriv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 f0 80 7d ?? c3 74 ?? 80 7d ?? c2 74 ?? 8d 45 ?? 50 8d 04 3e 50 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 00 ff 75 f0 ff 75 08 ff 55 f4 85 c0 (0f 8d ?? ??|7d ??) ff 75 1c ff 75 18 ff 75 14 ff 75 10 ff 75 f0 ff 75 08 ff 55 f4 89 45 0c 61 9d 8b 45 0c 8b e5 5d c2 18 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

