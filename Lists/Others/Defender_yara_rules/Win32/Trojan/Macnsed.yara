rule Trojan_Win32_Macnsed_A_2147646944_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Macnsed.A"
        threat_id = "2147646944"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Macnsed"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 6c 61 2f 67 74 73 6b 69 6e 66 6f 2e 61 73 70 78 3f 76 65 72 3d [0-4] 26 74 3d 72 62 26 6d 3d}  //weight: 1, accuracy: Low
        $x_1_2 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 00 00 63 00 74 00 6d 00 6f 00 6e 00}  //weight: 1, accuracy: High
        $x_1_3 = "|*@*|" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

