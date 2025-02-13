rule Backdoor_Win32_Ccinject_A_2147648306_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Ccinject.A"
        threat_id = "2147648306"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Ccinject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c7 44 24 04 20 03 00 00 c7 04 24 00 00 00 00 ff 95 a4 fb ff ff 52 52 89 04 24 ff d6 50 47 81 ff 80 84 1e 00}  //weight: 1, accuracy: High
        $x_1_2 = {c6 85 39 ff ff ff 69 c6 85 3a ff ff ff 6f c6 85 3b ff ff ff 6e 8d 7d 95 b1 0f f3 aa c6 45 95 56 c6 45 96 69 c6 45 97 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

