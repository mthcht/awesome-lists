rule Worm_Win32_Copali_B_2147687931_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Copali.B"
        threat_id = "2147687931"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Copali"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {74 6d 72 53 70 72 65 61 64 00}  //weight: 1, accuracy: High
        $x_1_2 = {74 6d 72 44 77 6e 6c 64 46 69 6c 65 00}  //weight: 1, accuracy: High
        $x_1_3 = {74 6d 72 52 65 67 65 64 69 74 00}  //weight: 1, accuracy: High
        $x_1_4 = {5a 00 31 00 59 00 32 00 58 00 33 00 57 00 34 00 56 00 35 00 55 00 36 00 54 00 37 00 53 00 38 00 52 00 39 00 51 00 30 00 50 00 4f 00 4e 00 4a 00 4d 00 4c 00 4b 00 49 00 48 00 47 00 45 00 46 00 43 00 44 00 42 00 41 00 7a 00 79 00 78 00 77 00 74 00 76 00 75 00 73 00 72 00 71 00 70 00 6c 00 6f 00 6e 00 6d 00 6b 00 6a 00 67 00 68 00 69 00 66 00 65 00 62 00 64 00 63 00 61 00 21 00 40 00 23 00 24 00 25 00 5e 00 26 00 2a 00 28 00 29 00 5f 00 2b 00 2d 00 3d 00 3a 00 2e 00 5c 00 2f 00 27 00 5b 00 5d 00 20 00 2c 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Copali_2147692436_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Copali"
        threat_id = "2147692436"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Copali"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 69 73 74 72 69 62 75 74 65 45 58 45 00}  //weight: 1, accuracy: High
        $x_1_2 = {6d 44 77 6e 6c 64 00}  //weight: 1, accuracy: High
        $x_1_3 = {6d 4b 69 6c 6c 50 72 6f 63 65 73 73 00}  //weight: 1, accuracy: High
        $x_1_4 = {74 6d 72 53 65 61 72 63 68 00}  //weight: 1, accuracy: High
        $x_1_5 = {74 6d 72 4c 6f 6f 70 00}  //weight: 1, accuracy: High
        $x_1_6 = {30 00 39 00 38 00 37 00 36 00 35 00 34 00 33 00 32 00 31 00 5a 00 59 00 58 00 57 00 56 00 55 00 54 00 53 00 52 00 51 00 50 00 4f 00 4e 00 4d 00 4c 00 4b 00 4a 00 49 00 48 00 47 00 46 00 45 00 44 00 43 00 42 00 41 00 7a 00 79 00 78 00 77 00 76 00 75 00 74 00 73 00 72 00 71 00 70 00 6f 00 6e 00 6d 00 6c 00 6b 00 6a 00 69 00 68 00 67 00 66 00 65 00 64 00 63 00 62 00 61 00 21 00 40 00 23 00 24 00 25 00 5e 00 26 00 2a 00 28 00 29 00 5f 00 2b 00 2d 00 3d 00 3a 00 2e 00 5c 00 2f 00 27 00 5b 00 5d 00 20 00 2c 00 00 00}  //weight: 1, accuracy: High
        $x_1_7 = {c7 45 fc 0c 00 00 00 ?? ?? ?? ?? ?? c7 45 fc 0d 00 00 00 66 c7 85 74 ff ff ff 60 1c 66 c7 85 78 ff ff ff 01 00 00 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

