rule Ransom_Win32_Voidlock_A_2147696948_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Voidlock.A"
        threat_id = "2147696948"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Voidlock"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 6d ff 8a 5e 5e 8a c1 d0 c0 32 c8 d0 c0 32 c8 d0 c0 32 c8 d0 c0 32 46 40 32 c1 32 c5 34 63}  //weight: 1, accuracy: High
        $x_1_2 = {8a 48 fc 30 08 8a 48 fd 30 48 01 8a 48 fe 30 48 02 8a 48 ff 30 48 03 83 c0 04 4a 75 e3}  //weight: 1, accuracy: High
        $x_1_3 = "%s.vernost" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

