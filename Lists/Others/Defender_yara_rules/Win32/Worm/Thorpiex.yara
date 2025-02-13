rule Worm_Win32_Thorpiex_A_2147687094_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Thorpiex.A"
        threat_id = "2147687094"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Thorpiex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {84 c9 74 0c 8a 4e 01 8a 5a 01 46 42 32 d9 74 f0 80 3a 00 74 0f}  //weight: 5, accuracy: High
        $x_5_2 = {6a 00 6a 0d 68 00 01 00 00 56 ff 15 ?? ?? ?? ?? 6a 00 6a 00 6a 10 57 ff d5 6a 00 6a 00 6a 08 57 ff d5 6a 00 6a 00 6a 02 57 ff d5}  //weight: 5, accuracy: Low
        $x_1_3 = "/imspam.htm" ascii //weight: 1
        $x_1_4 = {53 65 6e 64 20 4d 65 73 73 61 67 65 20 74 6f 20 47 72 6f 75 70 [0-32] 41 54 4c 3a 30 30 38 39 30 41 39 30}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

