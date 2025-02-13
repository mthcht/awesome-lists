rule Backdoor_Win32_Glupteba_G_2147762730_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Glupteba.G!MSR"
        threat_id = "2147762730"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3b 2d 0b 00 8b 15 04 ?? ?? ?? 88 0c 02 c3 14 8b 0d b8 ?? ?? ?? 8a 8c 01}  //weight: 1, accuracy: Low
        $x_1_2 = {53 e8 e9 e7 ff ff 83 c3 08 ff 4d fc 75 b1}  //weight: 1, accuracy: High
        $x_1_3 = {be 14 34 40 00 bf 28 ?? ?? 00 a5 a5 a5 66 a5 a4 5f 66 c7 05 29 ?? ?? 00 69 72 5e c3}  //weight: 1, accuracy: Low
        $x_1_4 = "VebtualProtect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

