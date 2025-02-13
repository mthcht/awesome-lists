rule Backdoor_Win32_Kawpfuni_A_2147697468_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Kawpfuni.A"
        threat_id = "2147697468"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Kawpfuni"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 54 01 ff 48 f6 d2 88 14 01 75 f4}  //weight: 1, accuracy: High
        $x_1_2 = {57 61 6b 65 75 70 20 74 69 6d 65 20 3d 20 32 30 25 30 32 64 3a 25 64 3a 25 64 0d 0a 5b 57 57 57 5d 0d 0a 25 73 0d 0a 5b 49 6e 66 65 63 74 5d 0d 0a 25 73}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

