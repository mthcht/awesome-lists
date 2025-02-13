rule Backdoor_Win32_Cinasquel_A_2147678322_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Cinasquel.A"
        threat_id = "2147678322"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Cinasquel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "xpdl3_init" ascii //weight: 2
        $x_2_2 = {63 3a 5c 57 69 6e 64 6f 77 73 5c 74 65 6d 70 5c [0-16] 2e 65 78 65}  //weight: 2, accuracy: Low
        $x_2_3 = {25 74 65 6d 70 5c 74 6d 70 [0-5] 5c [0-16] 2e 65 78 65}  //weight: 2, accuracy: Low
        $x_2_4 = "piress" wide //weight: 2
        $x_2_5 = "adminlv123" wide //weight: 2
        $x_2_6 = {6d 79 73 71 6c 2e 64 6c 6c 00 78 70 64 6c 33}  //weight: 2, accuracy: High
        $x_10_7 = {83 e8 04 74 3e 48 74 0e 48 8d 54 24 48 75 43}  //weight: 10, accuracy: High
        $x_2_8 = "(%s) portnumber (%d) osversion (%s)" ascii //weight: 2
        $x_10_9 = {8b 84 24 b0 00 00 00 83 e8 04 [0-16] 48 74 ?? 48 8d 54 24 48}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_2_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Cinasquel_B_2147685116_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Cinasquel.B"
        threat_id = "2147685116"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Cinasquel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "sf23_deinit" ascii //weight: 2
        $x_2_2 = {63 3a 5c 57 69 6e 64 6f 77 73 5c 74 65 6d 70 5c [0-16] 2e 65 78 65}  //weight: 2, accuracy: Low
        $x_2_3 = {6d 79 73 71 6c 2e 64 6c 6c 00 73 66 32 33}  //weight: 2, accuracy: High
        $x_2_4 = "(%s) portnumber (%d) osversion (%s)" ascii //weight: 2
        $x_2_5 = {5c 63 6e 61 31 32 [0-16] 2e 64 6c 6c}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

