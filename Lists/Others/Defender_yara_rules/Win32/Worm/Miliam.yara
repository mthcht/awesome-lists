rule Worm_Win32_Miliam_A_2147619718_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Miliam.A"
        threat_id = "2147619718"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Miliam"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "miniMail-version1.0" ascii //weight: 2
        $x_1_2 = {73 61 6e 74 61 2e 63 6c 61 75 73 40 6e 6f 72 74 68 70 6f 6c 65 2e 63 6f 6d 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {73 79 73 74 65 6d 2e 69 6e 69 [0-4] 45 78 70 6c 6f 72 65 72 2e 65 78 65 20 6d 69 6e 69 4d 61 69 6c 2e 65 78 65 [0-4] 73 68 65 6c 6c [0-4] 62 6f 6f 74}  //weight: 1, accuracy: Low
        $x_1_4 = {53 4d 54 50 20 45 6d 61 69 6c 20 41 64 64 72 65 73 73 [0-8] 3d [0-4] 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 41 63 63 6f 75 6e 74 20 4d 61 6e 61 67 65 72 5c 41 63 63 6f 75 6e 74 73}  //weight: 1, accuracy: Low
        $x_1_5 = "PRIVMSG ##niggah :Sent Mail to" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

