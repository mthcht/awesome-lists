rule Backdoor_Win32_Bittaru_A_2147645015_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Bittaru.A"
        threat_id = "2147645015"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Bittaru"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {3d 53 4f 4c 43 75 0f c7 05 [0-8] e9 be 00 00 00 3d 3a 44 4d 43}  //weight: 2, accuracy: Low
        $x_2_2 = {3d 44 48 4b 4c 75 09 e8 ?? ?? ?? ?? 0b c0 75 2d 3d 53 4c 53 50}  //weight: 2, accuracy: Low
        $x_1_3 = "=DLPUu" ascii //weight: 1
        $x_1_4 = {3d 4b 4f 4f 4c 75 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

