rule Worm_Win32_Slensnook_A_179516_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Slensnook.gen!A"
        threat_id = "179516"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Slensnook"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {32 c2 42 81 e2 ff 00 00 80 88 04 31 79 08 4a 81 ca 00 ff ff ff 42 41 83 f9 ?? 7c dd c6 46 ?? 00 8b c6 07 00 8a 84 0f}  //weight: 2, accuracy: Low
        $x_1_2 = "SNS-3.0." ascii //weight: 1
        $x_1_3 = {46 69 72 65 20 46 6f 78 53 4e 53 00}  //weight: 1, accuracy: High
        $x_1_4 = {2f 6d 65 2f 66 72 69 65 6e 64 73 3f 66 69 65 6c 64 73 3d 69 64 26 61 63 63 65 73 73 5f 74 6f 6b 65 6e 3d 25 73 00}  //weight: 1, accuracy: High
        $x_1_5 = {52 65 63 6f 76 65 72 65 64 20 50 57 73 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

