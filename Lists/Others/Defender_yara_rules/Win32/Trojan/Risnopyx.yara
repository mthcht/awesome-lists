rule Trojan_Win32_Risnopyx_A_2147685011_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Risnopyx.A"
        threat_id = "2147685011"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Risnopyx"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "PowerLocker Lock Module" ascii //weight: 1
        $x_1_2 = {70 75 62 6b 65 79 2e 62 69 6e 00 [0-3] 2e 72 61 6e 73 00}  //weight: 1, accuracy: Low
        $x_1_3 = {50 72 6f 63 2d 54 79 70 65 3a 20 34 2c [0-8] 45 4e 43 52 59 50 54 45 44 00}  //weight: 1, accuracy: Low
        $x_1_4 = {8b 44 24 08 8b 4c 24 04 6a 00 6a 00 6a 00 6a 00 6a 00 50 51 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

