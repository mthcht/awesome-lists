rule Backdoor_Win32_Taroca_A_2147689594_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Taroca.A"
        threat_id = "2147689594"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Taroca"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {34 6f 80 f1 70 88 44 24 5e a1 ?? ?? ?? ?? 88 4c 24 5c 8a c8 8a c4 34 75 80 f2 72 88 44 24 60 66 a1 ?? ?? ?? ?? 88 54 24 5d 8a d0 8a c4 80 f1 64 34 74 88 4c 24 5f 88 44 24 62 bf ?? ?? ?? ?? 83 c9 ff 33 c0 80 f2 63}  //weight: 3, accuracy: Low
        $x_1_2 = "application/x-ms-xbap" ascii //weight: 1
        $x_1_3 = "application/vnd.ms-xpsdocument" ascii //weight: 1
        $x_1_4 = "Set return time error = %d!" ascii //weight: 1
        $x_3_5 = {80 f1 49 88 4e 0e 8a 15 ?? ?? ?? ?? 80 f2 42 88 56 0f 8a 0d ?? ?? ?? ?? 80 f1 4d 88 4e 10 8a 15 ?? ?? ?? ?? 80 f2 4c 88 56 11 8a 0d ?? ?? ?? ?? 80 f1 6f 88 4e 12 8a 15 ?? ?? ?? ?? 80 f2 74 88 56 13 8a 0d ?? ?? ?? ?? 80 f1 75 88 4e 14 8a 15 ?? ?? ?? ?? 80 f2 73 88 56 15 8a 0d ?? ?? ?? ?? 80 f1 4d 88 4e 16 8a 15 ?? ?? ?? ?? 80 f2 53 88 56 17 5e}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

