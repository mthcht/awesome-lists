rule Trojan_Win32_Mariofev_A_2147611940_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Mariofev.A"
        threat_id = "2147611940"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Mariofev"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "19"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 75 dc 59 53 57 56 6a 10 89 45 cc ff 15}  //weight: 10, accuracy: High
        $x_2_2 = {6e 76 72 73 ?? 6c 33 32 2e 64 6c 6c}  //weight: 2, accuracy: Low
        $x_2_3 = "p i n i t _ d l l s" ascii //weight: 2
        $x_2_4 = "paso.el" ascii //weight: 2
        $x_2_5 = {74 65 72 6d 73 72 76 2e 64 6c 6c 00 54 53 45 6e 61 62 6c 65 64 00 00 00 66 44 65 6e 79 54 53 43 6f 6e 6e 65 63 74 69 6f 6e 73}  //weight: 2, accuracy: High
        $x_1_6 = "NtQuerySystemInformation" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Mariofev_2147617979_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Mariofev.gen!dll"
        threat_id = "2147617979"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Mariofev"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {47 65 74 4d 6f 64 75 6c 65 49 64 00 47 65 74 4d 6f 64 75 6c 65 56 65 72 73 69 6f 6e 00 4d 6f 64 75 6c 65 53 74 61 72 74 75 70 00 [0-64] 4f 6e 4b 65 72 6e 65 6c 45 76 65 6e 74 52 65 63 65 69 76 65 64 00}  //weight: 1, accuracy: Low
        $x_1_2 = {2e 64 6c 6c 00 47 65 74 4d 6f 64 75 6c 65 49 64 00 47 65 74 4d 6f 64 75 6c 65 56 65 72 73 69 6f 6e 00 4d 6f 64 75 6c 65 53 74 61 72 74 75 70 00 16 00 [0-16] 00 4d 6f 64}  //weight: 1, accuracy: Low
        $x_1_3 = {4d 46 43 34 32 2e 44 4c 4c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Mariofev_2147617979_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Mariofev.gen!dll"
        threat_id = "2147617979"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Mariofev"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_6_1 = {2e 64 6c 6c 00 47 65 74 4d 6f 64 75 6c 65 49 64 00 6b 65 5f 47 65 74 46 69 72 73 74 4f 62 6a 00 6b 65 5f 47 65 74 4d 6f 64 75 6c 65 56 65 72 73 69 6f 6e 00 6b 65 5f 47 65 74 4e 65 78 74 4f 62 6a 00 6b 65 5f 49 73 4d 6f 64 75 6c 65 45 78 69 73 74 73 00 6b 65 5f 4d 6f 64 75 6c 65 41 76 61 69 6c 61 62 6c 65 00 6b 65 5f 4e 6f 74 69 66 79 45 76 65 6e 74 00 6b 65 5f 52 61 6e 64 00 6b 65 5f 52 65 67 69 73 74 65 72 41 6e 64 4c 6f 61 64 4e 65 77 4d 6f 64 75 6c 65}  //weight: 6, accuracy: High
        $x_2_2 = "c:\\crashdump.log" ascii //weight: 2
        $x_2_3 = {6b 65 5f 54 65 72 6d 69 6e 61 74 65 4b 65 72 6e 65 6c 00}  //weight: 2, accuracy: High
        $x_2_4 = {6b 65 5f 70 61 6e 69 63 00}  //weight: 2, accuracy: High
        $x_1_5 = "ReadProcessMemory" ascii //weight: 1
        $x_1_6 = "LoadResource" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_6_*) and 1 of ($x_1_*))) or
            ((1 of ($x_6_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Mariofev_B_2147637994_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Mariofev.B"
        threat_id = "2147637994"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Mariofev"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {81 f9 a7 29 03 ca c6 44 24 0c e9 c6 44 24 0d f5 88 5c 24 0e 88 5c 24 0f 88 5c 24 10 c6 44 24 11 90 75 05}  //weight: 2, accuracy: High
        $x_2_2 = {80 f9 c2 75 4d 80 38 90 75 48 80 78 01 90 75 42 8d 54 24 10 8d 4c 24 1c 52 6a 05}  //weight: 2, accuracy: High
        $x_1_3 = "CPUInfo:Count:%u Type:%u" ascii //weight: 1
        $x_1_4 = "Inject Core PROCESS = %s load module = %s RESULT = %i" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

