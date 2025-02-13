rule Trojan_Win32_Kuang_E_2147623646_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kuang.E"
        threat_id = "2147623646"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kuang"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {77 65 69 72 64 31 37 33 40 79 61 68 6f 6f 2e 63 6f 6d 00 20 62 79 20 57 65 69 72 64 00}  //weight: 1, accuracy: High
        $x_1_2 = {45 58 45 00 00 4f 70 65 6e 20 6b 75 61 6e 67 32 20 70 53 65 6e 64 65 72}  //weight: 1, accuracy: High
        $x_1_3 = "Coded by Weird" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

