rule Trojan_Win32_Sobocat_A_2147733729_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sobocat.A"
        threat_id = "2147733729"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sobocat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = "add hkcu\\software\\classes\\ms-settings\\shell\\open\\command" wide //weight: 5
        $x_5_2 = "delegateexecute" wide //weight: 5
        $x_5_3 = "fodhelper.exe" wide //weight: 5
        $x_1_4 = {77 00 6d 00 69 00 63 00 20 00 2f 00 6e 00 61 00 6d 00 65 00 73 00 70 00 61 00 63 00 65 00 3a 00 [0-32] 5c 00 6d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 64 00 65 00 66 00 65 00 6e 00 64 00 65 00 72 00 20 00 63 00 6c 00 61 00 73 00 73 00 20 00 6d 00 73 00 66 00 74 00 5f 00 6d 00 70 00 70 00 72 00 65 00 66 00 65 00 72 00 65 00 6e 00 63 00 65 00}  //weight: 1, accuracy: Low
        $x_1_5 = {77 00 6d 00 69 00 63 00 20 00 2f 00 6e 00 61 00 6d 00 65 00 73 00 70 00 61 00 63 00 65 00 3a 00 [0-32] 5c 00 6d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 70 00 72 00 6f 00 74 00 65 00 63 00 74 00 69 00 6f 00 6e 00 6d 00 61 00 6e 00 61 00 67 00 65 00 6d 00 65 00 6e 00 74 00 20 00 63 00 6c 00 61 00 73 00 73 00 20 00 6d 00 73 00 66 00 74 00 5f 00 6d 00 70 00 70 00 72 00 65 00 66 00 65 00 72 00 65 00 6e 00 63 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 1 of ($x_1_*))) or
            ((3 of ($x_5_*))) or
            (all of ($x*))
        )
}

