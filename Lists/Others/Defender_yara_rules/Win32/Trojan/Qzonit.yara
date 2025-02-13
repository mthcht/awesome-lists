rule Trojan_Win32_Qzonit_A_2147717910_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qzonit.A!bit"
        threat_id = "2147717910"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qzonit"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 36 38 43 35 41 34 41 39 37 46 30 46 46 41 35 39 41 41 37 37 45 30 45 44 33 44 35 43 43 45 34 42 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 36 39 42 31 41 34 41 42 37 43 37 41 46 41 32 45 41 41 30 44 45 31 39 31 33 46 35 38 43 45 33 41 33 44 43 34 38 39 30 41 44 46 30 43 37 34 37 44 39 46 37 46 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 36 39 42 36 44 46 41 41 37 41 37 39 46 41 35 44 41 41 37 36 45 30 39 43 33 41 35 44 43 46 34 38 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 37 61 63 31 33 62 33 61 61 38 32 31 33 36 61 66 61 33 30 39 30 63 35 31 33 37 00}  //weight: 1, accuracy: High
        $x_1_5 = {00 36 38 42 33 41 35 41 30 37 46 30 34 46 41 35 44 41 41 37 37 45 31 39 31 33 44 32 37 43 44 34 39 33 45 42 35 38 38 30 46 44 46 30 41 37 34 30 38 39 46 37 45 44 45 34 31 42 34 46 33 30 46 45 39 00}  //weight: 1, accuracy: High
        $x_1_6 = {00 55 30 39 47 56 46 64 42 55 6b 56 63 54 57 6c 6a 63 6d 39 7a 62 32 5a 30 58 46 64 70 62 6d 52 76 64 33 4e 63 51 33 56 79 63 6d 56 75 64 46 5a 6c 63 6e 4e 70 62 32 35 63 55 6e 56 75 58 41 3d 3d 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

