rule Trojan_Win32_Hosinject_A_2147683074_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Hosinject.A"
        threat_id = "2147683074"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Hosinject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 b2 6e b1 65 b3 72 b0 64 6a 01 68 ?? ?? ?? ?? c6 44 24 3c 43 c6 44 24 3d 6f 88 54 24 3e c6 44 24 3f 74 88 4c 24 40 88 54 24 41 c6 44 24 42 74 c6 44 24 44 54 c6 44 24 45 79 88 4c 24 47}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 04 50 6a 02 56 ff d7 8d 4c 24 5c 6a 04 51 6a 07 56 ff d7 8d 54 24 5c 6a 04 52 6a 08 56 ff d7}  //weight: 1, accuracy: High
        $x_1_3 = {8b 94 24 c0 00 00 00 8d 44 24 0c 53 8b 1d 28 90 40 00 50 8d 4c 24 18 6a 04 83 c2 08 51 52 56 ff d3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

