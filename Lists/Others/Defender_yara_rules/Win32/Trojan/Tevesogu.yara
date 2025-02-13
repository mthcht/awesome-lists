rule Trojan_Win32_Tevesogu_A_2147657511_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tevesogu.A"
        threat_id = "2147657511"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tevesogu"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 54 56 54 2e 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 00 77 00 69 00 6e 00 73 00 74 00 61 00 30 00 5c 00 64 00 65 00 66 00 61 00 75 00 6c 00 74 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {52 00 55 00 4e 00 44 00 4c 00 4c 00 33 00 32 00 2e 00 45 00 58 00 45 00 00 00 00 00 52 00 55 00 4e 00 41 00 53 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 00 72 00 75 00 6e 00 61 00 73 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {6a 00 6a 00 6a 04 6a 00 6a 01 68 00 00 00 40 68 ?? ?? 03 10 68 ?? ?? ?? ?? 6a 16 68 ?? ?? 03 10 8d 4d ec e8 ?? ?? 00 00 8b c8 e8 ?? ?? ff ff 50 ff 15 ?? ?? 03 10 89 45 f8 8d 4d ec e8 ?? ?? 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

