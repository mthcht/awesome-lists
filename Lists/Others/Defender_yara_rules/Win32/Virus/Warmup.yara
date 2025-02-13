rule Virus_Win32_Warmup_2147602578_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Warmup.gen!dll"
        threat_id = "2147602578"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Warmup"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {c6 03 6d c6 43 01 74 c6 43 02 7a c6 43 03 77 c6 43 04 35 c6 43 05 2d c6 43 06 22 c6 43 07 72 c6 43 08 77 c6 43 09 79 c6 43 0a 29 c6 43 0b 6d c6 43 0c 6e c6 43 0d 6c c6 43 0e 66 c6 43 0f 6b c6 43 10 36 c6 43 11 3f c6 43 12 21 c6 43 13 6c c6 43 14 68 c6 43 15 71 c6 43 16 2f c6 43 17 69 c6 43 18 68 c6 43 19 60 c6 43 1a 66 c6 43 1b 23 c6 43 1c 71 c6 43 1d 78 c6 43 1e 7a 8d 45 f0 8b d3 b9 1f 00 00 00}  //weight: 10, accuracy: High
        $x_1_2 = {64 6c 6c 2e 74 78 74 00}  //weight: 1, accuracy: High
        $x_1_3 = {43 68 65 63 6b 76 69 70 00}  //weight: 1, accuracy: High
        $x_1_4 = {55 70 2e 77 6f 72 6d 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Virus_Win32_Warmup_A_2147602579_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Warmup.gen!A"
        threat_id = "2147602579"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Warmup"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "MZUpWormcctv" ascii //weight: 10
        $x_1_2 = {64 65 62 75 67 67 65 72 00}  //weight: 1, accuracy: High
        $x_1_3 = {49 63 65 53 77 6f 72 64 2e 63 6f 6d 00}  //weight: 1, accuracy: High
        $x_1_4 = {6d 73 63 6f 6e 66 69 67 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_5 = {6e 6f 64 33 32 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_6 = {48 69 6a 61 63 6b 54 68 69 73 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_7 = {61 75 74 6f 72 75 6e 73 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_8 = {55 6d 78 41 74 74 61 63 68 6d 65 6e 74 2e 65 78 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

