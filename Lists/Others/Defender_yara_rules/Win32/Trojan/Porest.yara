rule Trojan_Win32_Porest_2147708300_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Porest!dha"
        threat_id = "2147708300"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Porest"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e8 10 33 c2 69 c0 6b ca eb 85 8b c8 c1 e9 0d 33 c8}  //weight: 1, accuracy: High
        $x_1_2 = {8a 10 00 55 ?? 0f b6 4d ?? 8d 8c 0d ?? ?? ?? ?? 8a 19 88 18 88 11 0f b6 00 0f b6 ca 03 c8 81 e1 ff 00 00 00 8a 84 0d ?? ?? ?? ?? 32 04 37 88 06 46 ff 4d ?? 75 bc}  //weight: 1, accuracy: Low
        $x_1_3 = {8a 19 88 18 88 11 0f b6 00 0f b6 ca 03 c8 81 e1 ff 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = "Mozilla/5.0 (Windows NT 6.1; Win32; x86; rv:20.0) Gecko/20100101 Firefox/20.0" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

