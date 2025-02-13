rule Worm_Win32_Nusump_A_2147637288_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Nusump.gen!A"
        threat_id = "2147637288"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Nusump"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4e 45 57 20 49 4e 46 45 43 54 45 44 20 42 59 20 55 53 42 00}  //weight: 1, accuracy: High
        $x_1_2 = {69 6e 64 65 78 2e 70 68 70 3f 69 64 3d 25 73 26 63 6f 3d 25 73 26 75 73 3d 25 73 26 6f 73 3d 25 73 26 76 72 3d 25 73 26 64 74 00}  //weight: 1, accuracy: High
        $x_1_3 = {81 3f 2e 6d 73 6e 75}  //weight: 1, accuracy: High
        $x_1_4 = {81 3f 2e 64 77 6e 75}  //weight: 1, accuracy: High
        $x_1_5 = {81 3f 2e 75 73 62 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Worm_Win32_Nusump_B_2147644649_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Nusump.gen!B"
        threat_id = "2147644649"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Nusump"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 3f 2e 67 6d 6c 75}  //weight: 1, accuracy: High
        $x_1_2 = {81 3f 2e 64 77 6e 75}  //weight: 1, accuracy: High
        $x_1_3 = {81 3f 2e 75 73 62 75}  //weight: 1, accuracy: High
        $x_1_4 = {81 3f 2e 75 70 64 75}  //weight: 1, accuracy: High
        $x_1_5 = {81 3f 2e 73 70 6d 75}  //weight: 1, accuracy: High
        $x_1_6 = {81 3f 2e 73 74 6c 75}  //weight: 1, accuracy: High
        $x_1_7 = {88 ca 80 c2 41 b6 3a 51 52 8b 3c 24 54 ff 15 ?? ?? ?? ?? 83 f8 02 75}  //weight: 1, accuracy: Low
        $x_1_8 = {57 69 6e 64 c7 45 ?? 6f 77 73 4c c7 45 ?? 69 76 65 3a c7 45 ?? 6e 61 6d 65 c6 45 ?? 3d}  //weight: 1, accuracy: Low
        $x_1_9 = "SPAM HOTMAIL %u mail/s sended" ascii //weight: 1
        $x_1_10 = {5b 61 75 74 6f 72 75 6e 5d 00 4f 70 65 6e 20 3d 20 00 61 63 74 69 6f 6e 3d 41 62 72 69 72 20 63 61 72 70 65 74 61 20 70 61 72 61 20 76 65 72 20 61 72 63 68 69 76 6f 73}  //weight: 1, accuracy: High
        $x_1_11 = "MSN %u contact/s list extracted" ascii //weight: 1
        $x_1_12 = "resultado %u mails %u" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

