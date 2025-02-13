rule DoS_Win32_Sedeldos_A_2147815956_0
{
    meta:
        author = "defender2yara"
        detection_name = "DoS:Win32/Sedeldos.A!dha"
        threat_id = "2147815956"
        type = "DoS"
        platform = "Win32: Windows 32-bit platform"
        family = "Sedeldos"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 63 00 63 00 73 00 73 00 2e 00 65 00 78 00 65 00 [0-5] 2d 00 61 00 63 00 63 00 65 00 70 00 74 00 65 00 75 00 6c 00 61 00 [0-5] 2d 00 72 00 [0-10] 63 00 3a 00 5c 00 75 00 73 00 65 00 72 00 73 00}  //weight: 1, accuracy: Low
        $x_1_2 = {5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 63 00 63 00 73 00 73 00 2e 00 65 00 78 00 65 00 [0-5] 2d 00 61 00 63 00 63 00 65 00 70 00 74 00 65 00 75 00 6c 00 61 00 [0-5] 2d 00 72 00 [0-10] 63 00 3a 00 5c 00 70 00 72 00 6f 00 67 00 72 00 61 00 6d 00 64 00 61 00 74 00 61 00}  //weight: 1, accuracy: Low
        $x_1_3 = {5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 63 00 63 00 73 00 73 00 2e 00 65 00 78 00 65 00 [0-5] 2d 00 61 00 63 00 63 00 65 00 70 00 74 00 65 00 75 00 6c 00 61 00 [0-5] 2d 00 72 00 [0-10] 63 00 3a 00 5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 64 00 72 00 69 00 76 00 65 00 72 00 73 00 5c 00 2a 00}  //weight: 1, accuracy: Low
        $x_1_4 = {5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 63 00 63 00 73 00 73 00 2e 00 65 00 78 00 65 00 [0-5] 2d 00 61 00 63 00 63 00 65 00 70 00 74 00 65 00 75 00 6c 00 61 00 [0-5] 2d 00 72 00 [0-10] 64 00 3a 00 5c 00 2a 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule DoS_Win32_Sedeldos_B_2147823731_0
{
    meta:
        author = "defender2yara"
        detection_name = "DoS:Win32/Sedeldos.B!dha"
        threat_id = "2147823731"
        type = "DoS"
        platform = "Win32: Windows 32-bit platform"
        family = "Sedeldos"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {73 00 64 00 65 00 6c 00 65 00 74 00 65 00 2e 00 65 00 78 00 65 00 [0-10] 2d 00 61 00 63 00 63 00 65 00 70 00 74 00 65 00 75 00 6c 00 61 00 [0-10] 2d 00 71 00 [0-10] 63 00 3a 00 5c 00 75 00 73 00 65 00 72 00 73 00}  //weight: 1, accuracy: Low
        $x_1_2 = {73 00 64 00 65 00 6c 00 65 00 74 00 65 00 2e 00 65 00 78 00 65 00 [0-10] 2d 00 61 00 63 00 63 00 65 00 70 00 74 00 65 00 75 00 6c 00 61 00 [0-10] 2d 00 71 00 [0-10] 63 00 3a 00 5c 00 70 00 72 00 6f 00 67 00 72 00 61 00 6d 00 64 00 61 00 74 00 61 00}  //weight: 1, accuracy: Low
        $x_1_3 = {73 00 64 00 65 00 6c 00 65 00 74 00 65 00 2e 00 65 00 78 00 65 00 [0-10] 2d 00 61 00 63 00 63 00 65 00 70 00 74 00 65 00 75 00 6c 00 61 00 [0-10] 2d 00 71 00 [0-10] 63 00 3a 00 5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00}  //weight: 1, accuracy: Low
        $x_1_4 = {73 00 64 00 65 00 6c 00 65 00 74 00 65 00 2e 00 65 00 78 00 65 00 [0-10] 2d 00 61 00 63 00 63 00 65 00 70 00 74 00 65 00 75 00 6c 00 61 00 [0-10] 2d 00 71 00 [0-10] 64 00 3a 00}  //weight: 1, accuracy: Low
        $x_1_5 = {73 00 64 00 65 00 6c 00 65 00 74 00 65 00 2e 00 65 00 78 00 65 00 [0-10] 2d 00 61 00 63 00 63 00 65 00 70 00 74 00 65 00 75 00 6c 00 61 00 [0-10] 2d 00 71 00 [0-10] 65 00 3a 00}  //weight: 1, accuracy: Low
        $x_1_6 = {73 00 64 00 65 00 6c 00 65 00 74 00 65 00 2e 00 65 00 78 00 65 00 [0-10] 2d 00 61 00 63 00 63 00 65 00 70 00 74 00 65 00 75 00 6c 00 61 00 [0-10] 2d 00 71 00 [0-10] 66 00 3a 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

