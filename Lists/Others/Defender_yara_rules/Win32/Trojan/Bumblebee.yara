rule Trojan_Win32_Bumblebee_DD_2147830305_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bumblebee.DD!MTB"
        threat_id = "2147830305"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bumblebee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 f8 8b 4d bc 0f b7 14 41 8b 45 b8 8b 4d 0c 03 0c 90 89 4d e4 8b 55 f8 8b 45 bc 0f b7 0c 50 8b 55 b8 8b 45 08 03 04 8a 89 45 a8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bumblebee_PLS_2147831070_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bumblebee.PLS!MTB"
        threat_id = "2147831070"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bumblebee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {63 68 74 61 73 6b 73 2e 65 78 65 20 2f 46 20 2f 63 72 65 61 74 65 20 2f 73 63 20 6d 69 6e 75 74 65 20 2f 6d 6f 20 34 20 2f 54 4e 20 22 00 00 2f 53 54 20 30 34 3a 30 30 20 2f 54 52 20 22 77 73 63 72 69 70 74 20 2f 6e 6f 6c 6f 67 6f 20 00 41 64 76 61 70 69}  //weight: 1, accuracy: High
        $x_1_2 = "\\\\.\\pipe\\boost_process_auto_pipe" ascii //weight: 1
        $x_1_3 = "ZwProtectVirtualMemory" ascii //weight: 1
        $x_1_4 = "dataCheck" ascii //weight: 1
        $x_1_5 = "setPath" ascii //weight: 1
        $x_1_6 = "ZwAllocateVirtualMemory" ascii //weight: 1
        $x_1_7 = "ZwWriteVirtualMemory" ascii //weight: 1
        $x_1_8 = "ZwReadVirtualMemory" ascii //weight: 1
        $x_1_9 = "ZwGetContextThread" ascii //weight: 1
        $x_1_10 = "client_id" ascii //weight: 1
        $x_1_11 = "group_name" ascii //weight: 1
        $x_1_12 = "sys_version" ascii //weight: 1
        $x_1_13 = "client_version" ascii //weight: 1
        $x_1_14 = "task_state" ascii //weight: 1
        $x_1_15 = "task_result" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bumblebee_B_2147831103_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bumblebee.B"
        threat_id = "2147831103"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bumblebee"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "odbcconf" wide //weight: 1
        $x_1_2 = "regsvr" wide //weight: 1
        $x_1_3 = " /a " wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bumblebee_A_2147852809_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bumblebee.A"
        threat_id = "2147852809"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bumblebee"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {84 c0 74 09 33 c9 ff ?? ?? ?? ?? 00 cc 33 c9 e8 ?? ?? ?? 00 ?? 8b c8 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {84 c0 0f 85 ?? ?? 00 00 33 c9 e8 ?? ?? ?? ?? 48 8b c8 e8 ?? ?? ?? ?? 48 8d 85}  //weight: 1, accuracy: Low
        $x_1_3 = {48 8b c8 e8 ?? ?? ?? ?? 83 ca ff 48 8b 0d ?? ?? ?? ?? ff 15 07 00 33 c9 e8}  //weight: 1, accuracy: Low
        $x_1_4 = {4f 00 00 00 48 8d ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? ?? ?? ?? 48 8d ?? ?? ?? ?? ?? ba 4f 00 00 00 e8 ?? ?? ?? ?? ?? ?? ?? 48 8d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

