rule Trojan_Win32_SuspSliverLoader_A_2147971123_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspSliverLoader.A"
        threat_id = "2147971123"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspSliverLoader"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "VirtualAlloc" ascii //weight: 3
        $x_3_2 = "VirtualProtect" ascii //weight: 3
        $x_3_3 = "CreateThread" ascii //weight: 3
        $x_2_4 = "WaitForSingleObject" ascii //weight: 2
        $x_2_5 = "WSAStartup" ascii //weight: 2
        $x_2_6 = "recv" ascii //weight: 2
        $x_1_7 = "closesocket" ascii //weight: 1
        $x_4_8 = {41 b9 40 00 00 00 41 b8 00 30 00 00}  //weight: 4, accuracy: High
        $x_3_9 = {45 33 c9 41 b8 04 00 00 00}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_3_*) and 2 of ($x_2_*))) or
            ((3 of ($x_3_*) and 1 of ($x_1_*))) or
            ((3 of ($x_3_*) and 1 of ($x_2_*))) or
            ((4 of ($x_3_*))) or
            ((1 of ($x_4_*) and 3 of ($x_2_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_4_*) and 2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_SuspSliverLoader_B_2147971124_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspSliverLoader.B"
        threat_id = "2147971124"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspSliverLoader"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "VirtualAlloc" ascii //weight: 3
        $x_3_2 = "VirtualProtect" ascii //weight: 3
        $x_3_3 = "CreateThread" ascii //weight: 3
        $x_2_4 = "WSAStartup" ascii //weight: 2
        $x_2_5 = "recv" ascii //weight: 2
        $x_1_6 = "AllocConsole" ascii //weight: 1
        $x_1_7 = "FindWindowA" ascii //weight: 1
        $x_1_8 = "ShowWindow" ascii //weight: 1
        $x_4_9 = {41 b9 40 00 00 00 41 b8 00 30 00 00}  //weight: 4, accuracy: High
        $x_3_10 = {45 33 c9 41 b8 04 00 00 00}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_3_*) and 2 of ($x_2_*))) or
            ((3 of ($x_3_*) and 1 of ($x_1_*))) or
            ((3 of ($x_3_*) and 1 of ($x_2_*))) or
            ((4 of ($x_3_*))) or
            ((1 of ($x_4_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 3 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_4_*) and 2 of ($x_3_*))) or
            (all of ($x*))
        )
}

