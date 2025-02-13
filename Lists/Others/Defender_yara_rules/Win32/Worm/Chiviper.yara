rule Worm_Win32_Chiviper_A_2147608846_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Chiviper.A"
        threat_id = "2147608846"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Chiviper"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 3e 33 d2 59 f7 f1 46 83 fe 0a 8a 82 ?? ?? ?? ?? 88 86 ?? ?? ?? ?? 7c e2}  //weight: 1, accuracy: Low
        $x_1_2 = {80 3e 00 75 04 8b 74 24 14 8a 0e 28 08 8a 08 8a 16 32 d1 46 88 10 40 4f 75 e6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Chiviper_B_2147608859_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Chiviper.B"
        threat_id = "2147608859"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Chiviper"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 3e 33 d2 59 f7 f1 (46|47) 83 (fe|ff) 08 8a 82 ?? ?? ?? ?? 88 44 (35|3d) f3 7c e4 8d 85 f0 fe ff ff 50 68 04 01 00 00 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {68 40 77 1b 00 (ff 15 ?? ?? ?? ??|ff ??) e9}  //weight: 1, accuracy: Low
        $x_1_3 = {25 73 5c 25 73 2e 70 69 66 00}  //weight: 1, accuracy: High
        $x_1_4 = {5c 77 73 6f 63 6b 33 32 2e 64 6c 6c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Chiviper_C_2147618792_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Chiviper.C"
        threat_id = "2147618792"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Chiviper"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 74 24 14 8a 0e 28 08 8a 08 8a 16 32 d1 46 88 10 40 4f 75 e6}  //weight: 2, accuracy: High
        $x_2_2 = {8d 45 ec 50 ff 15 ?? ?? ?? ?? 83 f8 03 74 05 83 f8 02 75 0a 8d 45 ec 50 e8 ?? ?? 00 00 59 fe c3 80 fb 5a 7c c4}  //weight: 2, accuracy: Low
        $x_2_3 = {8a 08 2a ca 32 ca 88 08 40 4e 75 f4}  //weight: 2, accuracy: High
        $x_1_4 = "$AUTORUINF" ascii //weight: 1
        $x_1_5 = "mac=%s&ver=" ascii //weight: 1
        $x_1_6 = {25 73 5c 61 64 6d 69 6e 24 5c [0-8] 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_7 = "rs=createObject(\"Wscript.shell\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

