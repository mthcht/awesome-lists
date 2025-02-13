rule TrojanDropper_Win32_Genasom_B_2147631108_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Genasom.B"
        threat_id = "2147631108"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Genasom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 2e 65 78 65 [0-3] e8 ?? ?? ff ff 6a 00 6a 00 6a 02 6a 00 6a 01 68 00 00 00 40}  //weight: 1, accuracy: Low
        $x_1_2 = {83 c0 04 c1 ?? 0d 3d ?? ?? 00 00 72 e8}  //weight: 1, accuracy: Low
        $x_1_3 = {74 dc 00 00 00 83 c4 04 b8 2e 74 6d 70}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Genasom_C_2147694709_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Genasom.C"
        threat_id = "2147694709"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Genasom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "sc stop MsMpSvc" ascii //weight: 1
        $x_1_2 = {57 69 6e 44 65 66 65 6e 64 20 73 74 61 72 74 3d 20 22 64 69 73 61 62 6c 65 64 22 [0-4] 53 69 6c 65 6e 74 3d 31}  //weight: 1, accuracy: Low
        $x_1_3 = "system32\\lsassw86s.exe -i" ascii //weight: 1
        $x_1_4 = "lsassw86s.exe" wide //weight: 1
        $x_1_5 = "config WinDefend start= \"disabled" wide //weight: 1
        $x_1_6 = "Bro&wse" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

