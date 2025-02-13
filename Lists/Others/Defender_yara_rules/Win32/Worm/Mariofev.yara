rule Worm_Win32_Mariofev_A_2147607910_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Mariofev.A"
        threat_id = "2147607910"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Mariofev"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "31AC70412E939D72A9234CDEBB1AF5867B" ascii //weight: 1
        $x_1_2 = "31897356954C2CD3D41B221E3F24F99BBA" ascii //weight: 1
        $x_1_3 = "31C2E1E4D78E6A11B88DFA803456A1FFA5" ascii //weight: 1
        $x_1_4 = {68 6f 2e 6c 6e 00 00 00 31 00 00 00 6d 6e 2e 6e 00 00 00 00 36 00 00 00 62 6d 66 2e 63 73 00 00 38 00 00 00 6b 6f 2e 6f 00 00 00 00 39 00 00 00 63 63 73 2e 73 6f 00 00 37}  //weight: 1, accuracy: High
        $x_2_5 = "nview.dll" ascii //weight: 2
        $x_1_6 = "ke_RegisterAndLoadNewModule" ascii //weight: 1
        $x_1_7 = "CreateToolhelp32Snapshot" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Mariofev_A_2147608044_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Mariofev.A"
        threat_id = "2147608044"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Mariofev"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "52"
        strings_accuracy = "Low"
    strings:
        $x_50_1 = {47 65 74 4d 6f 64 75 6c 65 49 64 00 47 65 74 4d 6f 64 75 6c 65 56 65 72 73 69 6f 6e 00 4d 6f 64 75 6c 65 53 74 61 72 74 75 70 00 [0-64] 4f 6e 4b 65 72 6e 65 6c 45 76 65 6e 74 52 65 63 65 69 76 65 64 00}  //weight: 50, accuracy: Low
        $x_2_2 = "ModLightHttpCom.dll" ascii //weight: 2
        $x_2_3 = "ModCBackSocks.dll" ascii //weight: 2
        $x_2_4 = "ModCCSniffer.dll" ascii //weight: 2
        $x_2_5 = "ModSniffer.dll" ascii //weight: 2
        $x_2_6 = "ModSMBinf.dll" ascii //weight: 2
        $x_2_7 = "ModDevInf.dll" ascii //weight: 2
        $x_2_8 = "ModMailGrabber.dll" ascii //weight: 2
        $x_2_9 = "libsdsd.dll" ascii //weight: 2
        $x_2_10 = "ModCommunication.dll" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_50_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Mariofev_B_2147616589_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Mariofev.B"
        threat_id = "2147616589"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Mariofev"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "31"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {00 64 6c 6c 63 61 63 68 65 5c 75 73 65 72 33 32 2e 64 6c 6c 00}  //weight: 10, accuracy: High
        $x_10_2 = {00 20 70 20 69 20 6e 20 69 20 74 20 5f 20 64 20 6c 20 6c 20 73}  //weight: 10, accuracy: High
        $x_10_3 = {46 57 20 50 41 53 53 45 44 00 00 00 68 74 74 70 3a 2f 2f 6d 61 69 6c 2e 72 75}  //weight: 10, accuracy: High
        $x_1_4 = {2e 64 6c 6c 00 47 65 74 4d 6f 64 75 6c 65 49 64 00 6b 65 5f 47 65 74 46 69 72 73 74 4f 62 6a}  //weight: 1, accuracy: High
        $x_1_5 = {33 32 00 6e 76 [0-4] 33 32 2e 64 6c 6c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Mariofev_C_2147616590_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Mariofev.C"
        threat_id = "2147616590"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Mariofev"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 64 6c 6c 63 61 63 68 65 5c 75 73 65 72 33 32 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 20 70 20 69 20 6e 20 69 20 74 20 5f 20 64 20 6c 20 6c 20 73}  //weight: 1, accuracy: High
        $x_1_3 = {6e 76 72 73 ?? 6c [0-2] 2e 64 6c 6c [0-4] 6e 76 72 73}  //weight: 1, accuracy: Low
        $x_1_4 = "Windows NT\\CURRENTVERSION\\WINDOWS" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Mariofev_A_2147618336_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Mariofev.gen!A"
        threat_id = "2147618336"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Mariofev"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {68 cc 01 00 00 68 68 01 00 00 e8 ?? ?? 00 00 69 c0 e8 03 00 00 83 c4 10 50 ff d3}  //weight: 3, accuracy: Low
        $x_2_2 = {8b 45 0c 8a 04 07 32 c3 fe c3 80 fb ff 88 45 ec 76 02 32 db ff 75 ec}  //weight: 2, accuracy: High
        $x_1_3 = "CPUInfo:Count:%u Type:%u" ascii //weight: 1
        $x_1_4 = "KasperskyLab\\protected\\AVP7" ascii //weight: 1
        $x_1_5 = {6b 65 5f 54 65 72 6d 69 6e 61 74 65 4b 65 72 6e 65 6c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

