rule Trojan_Win32_Detbosit_A_2147740601_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Detbosit.A"
        threat_id = "2147740601"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Detbosit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "TouchMeNot_.txt" wide //weight: 1
        $x_1_2 = {41 00 64 00 6d 00 69 00 6e 00 69 00 73 00 74 00 72 00 61 00 74 00 6f 00 72 00 [0-32] 55 00 73 00 65 00 72 00 20 00 69 00 73 00 20 00 3a 00 [0-32] 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 6e 00 65 00 74 00 2e 00 65 00 78 00 65 00 [0-32] 75 00 73 00 65 00 72 00 [0-32] 2f 00 64 00 6f 00 6d 00 61 00 69 00 6e 00}  //weight: 1, accuracy: Low
        $x_1_3 = "boost::" ascii //weight: 1
        $x_1_4 = "money_get@" ascii //weight: 1
        $x_1_5 = {77 00 69 00 6e 00 6c 00 6f 00 67 00 6f 00 6e 00 2e 00 65 00 78 00 65 00 [0-16] 50 00 68 00 79 00 73 00 69 00 63 00 61 00 6c 00 44 00 69 00 73 00 6b 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

