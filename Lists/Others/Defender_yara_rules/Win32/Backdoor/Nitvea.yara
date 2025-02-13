rule Backdoor_Win32_Nitvea_A_2147655597_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Nitvea.A"
        threat_id = "2147655597"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Nitvea"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 44 30 ff 24 0f 32 d8 80 f3 0a 8d 45 fc e8 ?? ?? ?? ?? 8b 55 fc 8a 54 3a ff 80 e2 f0 02 d3 88 54 38 ff}  //weight: 1, accuracy: Low
        $x_1_2 = {25 70 72 6f 67 66 69 6c 65 73 25 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 69 65 78 70 6c 6f 72 65 2e 65 78 65 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 68 74 74 70 5c 73 68 65 6c 6c 5c 6f 70 65 6e 5c 63 6f 6d 6d 61 6e 64 5c 00}  //weight: 1, accuracy: Low
        $x_1_3 = {25 41 70 70 44 61 74 61 25 5c 53 65 72 76 65 72 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_4 = "CF61C1F1514F173060258CF792DDF551" ascii //weight: 1
        $x_1_5 = {5c 6d 65 6c 74 20 22 00}  //weight: 1, accuracy: High
        $x_1_6 = "DLLFILE" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

