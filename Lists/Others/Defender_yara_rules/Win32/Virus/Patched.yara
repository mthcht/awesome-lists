rule Virus_Win32_Patched_C_2147612054_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Patched.C"
        threat_id = "2147612054"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Patched"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 08 40 13 f9 c1 c1 08 0a c9 75 f4 3b 7d 0c 59 e0 e7}  //weight: 1, accuracy: High
        $x_1_2 = {66 81 e2 00 f0 81 ea 00 10 00 00 e8 04 00 00 00 e8 00 00 00 83 c4 04 66 81 3a 4d 5a 75 e2 8b c2 03 52 3c 80 3a 50 75 d8 80 7a 01 45 75 d2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

