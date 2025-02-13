rule Trojan_Win32_Gontu_B_2147627708_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gontu.B!dll"
        threat_id = "2147627708"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gontu"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2a 00 5c 00 41 00 44 00 3a 00 5c 00 57 00 75 00 20 00 54 00 6f 00 6e 00 67 00 5c 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 73 00 26 00 43 00 6f 00 64 00 65 00 73 00 5c 00 [0-32] 5c 00 42 00 72 00 6f 00 77 00 73 00 65 00 72 00 48 00 65 00 6c 00 70 00 65 00 72 00 2e 00 76 00 62 00 70 00}  //weight: 10, accuracy: Low
        $x_1_2 = {42 72 6f 77 73 65 72 48 65 6c 70 65 72 2e 64 6c 6c [0-4] 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}

