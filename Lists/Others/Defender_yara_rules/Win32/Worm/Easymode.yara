rule Worm_Win32_Easymode_A_2147598566_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Easymode.A"
        threat_id = "2147598566"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Easymode"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {83 c4 10 66 81 7d b8 4d 5a 74}  //weight: 2, accuracy: High
        $x_3_2 = {0f be 45 d4 83 f8 61 74 ?? 0f be 55 d4 83 fa 41 74}  //weight: 3, accuracy: Low
        $x_1_3 = "[AutoRun]" ascii //weight: 1
        $x_1_4 = "shell\\explore\\Command=" ascii //weight: 1
        $x_1_5 = "WriteProcessMemory" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

