rule TrojanDropper_Win32_Matcash_2147804044_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Matcash"
        threat_id = "2147804044"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Matcash"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "43"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "InternetOpenUrlA" ascii //weight: 10
        $x_10_2 = "ShellExecuteA" ascii //weight: 10
        $x_10_3 = "RegSetValueExA" ascii //weight: 10
        $x_10_4 = "UnhookWindowsHookEx" ascii //weight: 10
        $x_1_5 = {2f 63 61 70 74 75 72 65 38 2f 00 00 2f 6d 63 61 73 68 2f 00 68 74 74 70 3a 2f 2f}  //weight: 1, accuracy: High
        $x_1_6 = {77 65 62 6e 6f 31 00 00 63 68 65 63 6b 2e 70 68 70 3f 6d 61 63 3d}  //weight: 1, accuracy: High
        $x_1_7 = {5c 63 68 38 38 2e 74 6d 70 00 00 00 2e 64 65 6c 65 74 65 64}  //weight: 1, accuracy: High
        $x_1_8 = {2e 65 78 65 00 00 00 00 75 73 65 00 2f 00 00 00 73 74 61 72 74 75 70 00 6f 6e 63 65}  //weight: 1, accuracy: High
        $x_1_9 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 4d 61 69 6e 00 00 00 2e 45 58 45}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

