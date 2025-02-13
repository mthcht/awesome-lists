rule Trojan_Win32_Narkean_A_2147682447_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Narkean.A"
        threat_id = "2147682447"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Narkean"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {7e 11 8b 4d ec 8a 1c 08 80 c3 8f 88 1c 08 40 3b c2 7c ef b8}  //weight: 1, accuracy: High
        $x_1_2 = {4f 63 65 61 6e 41 72 6b 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

