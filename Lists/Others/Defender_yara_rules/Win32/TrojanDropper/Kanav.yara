rule TrojanDropper_Win32_Kanav_A_2147680330_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Kanav.A"
        threat_id = "2147680330"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Kanav"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c3 6a 00 68 80 00 00 00 6a 02 6a 00 6a 00 68 00 00 00 40 68 ?? ?? ?? ?? ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {c0 e1 04 02 cb 8a 9c 24 1c 08 00 00 32 cb 45 88 4c 34 10 8b fa 83 c9 ff 33 c0 46 f2 ae f7 d1 49 3b f1}  //weight: 1, accuracy: High
        $x_1_3 = "81A6A8D20CA2AE" ascii //weight: 1
        $x_1_4 = "FindResource error is 0x%08x" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Kanav_B_2147680333_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Kanav.B"
        threat_id = "2147680333"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Kanav"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "c:\\windows\\calc1.exe" ascii //weight: 1
        $x_1_2 = "%s\\AYLaunch.exe" ascii //weight: 1
        $x_1_3 = "%s\\usp10.dll.bak" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

