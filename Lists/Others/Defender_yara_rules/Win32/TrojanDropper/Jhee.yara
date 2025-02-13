rule TrojanDropper_Win32_Jhee_V_2147607842_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Jhee.V"
        threat_id = "2147607842"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Jhee"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {89 10 89 50 04 89 50 08 89 50 0c ff d7 99 b9 1a 00 00 00 be 01 00 00 00 f7 f9 80 c2 61 3b de 88 55 00 7e 19 ff d7}  //weight: 2, accuracy: High
        $x_1_2 = {62 68 6f 2e 64 6c 6c [0-16] 70 6c 61 79 2e 64 6c 6c [0-16] 73 65 72 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_3 = {31 2e 72 6d [0-16] 31 2e 74 78 74 [0-16] 31 2e 62 6d 70 [0-16] 31 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_4 = "fuckyou" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

