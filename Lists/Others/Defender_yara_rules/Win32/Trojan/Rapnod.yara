rule Trojan_Win32_Rapnod_A_2147652018_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rapnod.A"
        threat_id = "2147652018"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rapnod"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\Undercode\\[MALWARES]\\Pandora" ascii //weight: 1
        $x_1_2 = {64 6f 77 6e 68 6f 73 74 00}  //weight: 1, accuracy: High
        $x_1_3 = {76 65 72 75 72 6c 00}  //weight: 1, accuracy: High
        $x_1_4 = {45 76 69 74 61 72 55 41 43 00}  //weight: 1, accuracy: High
        $x_1_5 = {76 61 6c 69 64 75 72 6c 00}  //weight: 1, accuracy: High
        $x_1_6 = {43 00 3a 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 [0-32] 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_7 = "C:\\Windows\\system32\\drivers\\etc\\hosts" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

