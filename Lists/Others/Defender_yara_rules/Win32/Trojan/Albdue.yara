rule Trojan_Win32_Albdue_A_2147597897_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Albdue.A"
        threat_id = "2147597897"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Albdue"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 7d fc 02 75 2e 8b 45 fc 6a 02 99 59 c7 45 f0 bb 01 00 00 f7 f9 8d 85 0c ff ff ff 85 d2 74 06 8d 85 5c ff ff ff}  //weight: 1, accuracy: High
        $x_1_2 = {89 5d fc 57 50 e8 ?? ?? 00 00 83 c4 0c 83 ff 05 a3 ?? ?? 00 10 0f 8c ?? ?? 00 00 81 bd ?? ?? ff ff 21 40 23 24 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

