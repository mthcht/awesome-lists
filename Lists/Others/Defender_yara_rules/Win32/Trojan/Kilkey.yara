rule Trojan_Win32_Kilkey_A_2147620631_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kilkey.A"
        threat_id = "2147620631"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kilkey"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 45 fc 6a 00 6a 00 6a 00 6a 00 6a 00 68 ?? ?? ?? ?? 6a 00 6a 02 6a 10 68 10 00 01 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? ff 75 fc e8 18 01 00 00 0b c0 74 17}  //weight: 10, accuracy: Low
        $x_10_2 = {77 69 6e 78 70 73 68 [0-4] 7a 7a 7a 70 73 68 00 63 3a 5c 77 69 6e}  //weight: 10, accuracy: Low
        $x_10_3 = {69 66 72 61 6d 65 3e 00 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 00 6b 69 6c 6c 6b 65 79}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

