rule Trojan_Win32_SharPyShell_STE_2147779122_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SharPyShell.STE"
        threat_id = "2147779122"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SharPyShell"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "SharPyShell" ascii //weight: 1
        $x_1_2 = "runtime_compiler_aes.dll" ascii //weight: 1
        $x_1_3 = {53 00 68 00 61 00 72 00 50 00 79 00 [0-10] 6d 00 73 00 63 00 6f 00 72 00 6c 00 69 00 62 00}  //weight: 1, accuracy: Low
        $x_1_4 = {53 68 61 72 50 79 [0-10] 6d 73 63 6f 72 6c 69 62}  //weight: 1, accuracy: Low
        $x_1_5 = {41 45 53 45 6e 63 00 41 45 53 44 65 63 00 52 75 6e}  //weight: 1, accuracy: High
        $x_1_6 = {47 65 74 42 79 74 65 73 00 63 6f 64 65 00 70 61 73 73 77 6f 72 64 00 41 72 72 61 79}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

