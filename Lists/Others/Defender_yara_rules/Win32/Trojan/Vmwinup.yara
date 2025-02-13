rule Trojan_Win32_Vmwinup_A_2147617071_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vmwinup.A"
        threat_id = "2147617071"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vmwinup"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 00 63 00 72 00 69 00 70 00 74 00 69 00 6e 00 67 00 2e 00 46 00 69 00 6c 00 65 00 53 00 79 00 73 00 74 00 65 00 6d 00 4f 00 62 00 6a 00 65 00 63 00 74 00 [0-8] 67 00 65 00 74 00 66 00 69 00 6c 00 65 00 [0-3] 41 00 74 00 74 00 72 00 69 00 62 00 75 00 74 00 65 00 73 00}  //weight: 1, accuracy: Low
        $x_1_2 = {26 00 00 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 76 00 6d 00 6e 00 61 00 74 00 2e 00 65 00 78 00 65 00 00 00 36 00 00 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 75 00 70 00 64 00 65 00 74 00 65 00 2e 00 6c 00 6f 00 67 00 00 00 0a 00 00 00 76 00 6d 00}  //weight: 1, accuracy: High
        $x_1_3 = "\\Windows Media Player\\wmpnetwk.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

