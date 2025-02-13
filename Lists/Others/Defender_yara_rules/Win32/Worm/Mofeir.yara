rule Worm_Win32_Mofeir_P_2147571815_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Mofeir.P"
        threat_id = "2147571815"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Mofeir"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {32 c0 f6 44 24 04 01 75 0a d1 6c 24 04 fe c0 3c 1a 7c ef 83 c0 41}  //weight: 2, accuracy: High
        $x_2_2 = {88 45 fc 8d 45 fc 50 ff 15 ?? ?? ?? ?? 83 f8 02 75 0b}  //weight: 2, accuracy: Low
        $x_2_3 = {8b 4c 24 04 32 c0 f6 c1 01 75 08 d1 e9 fe c0 3c 1a 7c f3 83 c0 41}  //weight: 2, accuracy: High
        $x_2_4 = {88 44 24 18 ff d7 83 f8 02 a1 ?? ?? ?? ?? 75 23}  //weight: 2, accuracy: Low
        $x_1_5 = "[AutoRun]" ascii //weight: 1
        $n_5_6 = "arunusb.hlp" ascii //weight: -5
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

