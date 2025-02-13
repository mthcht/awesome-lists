rule TrojanDownloader_Win32_Zamelcat_A_169464_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zamelcat.A"
        threat_id = "169464"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zamelcat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 1a 99 59 f7 f9 8d 45 08 50 53 83 c2 61 89 55 08 e8 ?? 00 00 00 59 4f 59 75 df}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 03 e8 80 ff ff ff 50 8d 85 ?? ?? ff ff 50 68 ?? ?? ?? ?? 8d 85 ?? ?? ff ff 56 50 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Zamelcat_D_178030_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zamelcat.D"
        threat_id = "178030"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zamelcat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff ff 56 50 ff 15 ?? ?? ?? ?? 83 c4 18 33 f6 1e 00 ff 15 ?? ?? ?? ?? 6a 03 e8 ?? ?? ?? ?? 50 8d 85 ?? ?? ff ff 50 68 ?? ?? ?? ?? 8d 85}  //weight: 1, accuracy: Low
        $x_1_2 = {3a 36 2f 2e 78 2f 05 00 2e 65 78 65 00 [0-16] 25 73 5c 25 73 2e 65 78 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

