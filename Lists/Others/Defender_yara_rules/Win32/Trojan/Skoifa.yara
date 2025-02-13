rule Trojan_Win32_Skoifa_A_2147744729_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Skoifa.A!MSR"
        threat_id = "2147744729"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Skoifa"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 65 74 75 70 3d 43 3a 5c 57 69 6e 64 6f 77 73 5c 53 79 73 74 65 6d 33 32 5c 6d 73 68 74 61 2e 65 78 65 20 68 74 74 70 3a 2f 2f [0-3] 2e [0-3] 2e [0-3] 2e [0-3] 2f 78 78 2f 64 76}  //weight: 1, accuracy: Low
        $x_1_2 = {53 68 6f 72 74 63 75 74 3d 54 2c 20 22 43 3a 5c 57 69 6e 64 6f 77 73 5c 53 79 73 74 65 6d 33 32 5c 6d 73 68 74 61 2e 65 78 65 20 20 68 74 74 70 3a 2f 2f [0-3] 2e [0-3] 2e [0-3] 2e [0-3] 2f 78 78 2f 64 76 22 2c 20 2c 20 2c 20 48 65 6c 50 50 61 6e 65 2c 20 43 3a 5c 57 69 6e 64 6f 77 73 5c 48 65 6c 70 50 61 6e 65 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_3 = "Setup=GSHword.docx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

