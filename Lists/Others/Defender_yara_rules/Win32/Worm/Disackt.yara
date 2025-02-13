rule Worm_Win32_Disackt_A_2147611250_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Disackt.A"
        threat_id = "2147611250"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Disackt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {72 5c 44 69 73 61 43 4b 54 00 52 75 6e 5c 4b 68 6d 65 72 20 56 69 72 75 73 00 6d 73 63}  //weight: 4, accuracy: High
        $x_2_2 = {00 4d 79 20 43 56 00}  //weight: 2, accuracy: High
        $x_2_3 = {4b 75 6e 74 68 79 00 00 4d 6f 64 65 6c 31}  //weight: 2, accuracy: High
        $x_1_4 = "RegSetValueExA" ascii //weight: 1
        $x_1_5 = "SetWindowTextA" ascii //weight: 1
        $x_1_6 = "PostMessageA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

