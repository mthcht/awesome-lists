rule Worm_Win32_Disnight_B_2147615102_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Disnight.B"
        threat_id = "2147615102"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Disnight"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4b 6e 69 67 68 74 2e 65 78 65 16 00 73 68 65 6c 6c 5c 65 78 70 6c 6f 72 65 5c 63 6f 6d 6d 61 6e 64 3d}  //weight: 1, accuracy: Low
        $x_1_2 = "Disk Knight" ascii //weight: 1
        $x_1_3 = {4b 6e 69 67 68 74 [0-4] 66 72 6d 4d 61 69 6e [0-4] 6d 6f 64 50 72 6f 63 [0-4] 6d 6f 64 53 6d 61 72 74 48 6f 6f 6b [0-4] 6d 6f 64 54 68 72 65 61 64 [0-4] 63 53 6d 61 72 74 48 6f 6f 6b [0-4] 6d 6f 64 53 79 73 54 72 61 79}  //weight: 1, accuracy: Low
        $x_1_4 = "\\autorun.inf" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

