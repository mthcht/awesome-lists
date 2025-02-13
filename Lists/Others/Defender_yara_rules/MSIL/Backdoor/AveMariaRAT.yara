rule Backdoor_MSIL_AveMariaRAT_A_2147835967_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/AveMariaRAT.A!MTB"
        threat_id = "2147835967"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMariaRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {06 0b 16 0c 2b 42 16 0d 2b 2c 07 08 09 28 ?? 00 00 06 28 ?? 00 00 06 28 ?? 00 00 06 28 ?? 00 00 06 28 ?? 00 00 06 28 ?? 00 00 06 d2 06 28 ?? 00 00 06 09 17 58 0d 09 17 fe 04 13 04 11 04 2d ca 06 17 58 0a 08 17 58 0c 08 20 ?? ?? ?? 00 fe 04 13 05 11 05 2d b0 7e}  //weight: 2, accuracy: Low
        $x_1_2 = "ToArray" ascii //weight: 1
        $x_1_3 = "ToWin32" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_AveMariaRAT_B_2147835973_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/AveMariaRAT.B!MTB"
        threat_id = "2147835973"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMariaRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0a 13 07 09 11 07 d2 6e 1e 11 06 5a 1f 3f 5f 62 60 0d 11 06 17 58 13 06 11 06 1e 32 de 09 69 8d 32 00 00 01 25 17 73 10 00 00 0a 13 04 06 6f 11 00 00 0a 1f 0d 6a 59}  //weight: 2, accuracy: High
        $x_1_2 = "VirtualAllocEx" ascii //weight: 1
        $x_1_3 = "CreateRemoteThread" ascii //weight: 1
        $x_1_4 = "Wow64SetThreadContext" ascii //weight: 1
        $x_1_5 = "NtResumeThread" ascii //weight: 1
        $x_1_6 = "ZwUnmapViewOfSection" ascii //weight: 1
        $x_1_7 = "NtWriteVirtualMemory" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_AveMariaRAT_C_2147837517_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/AveMariaRAT.C!MTB"
        threat_id = "2147837517"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMariaRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {03 04 1c d6 5d 8c}  //weight: 2, accuracy: High
        $x_2_2 = {da 9a 0b 73 ?? ?? 00 0a 0c 0e 00 06 74 ?? 00 00 01 6f ?? ?? 00 0a 03 1f 0a}  //weight: 2, accuracy: Low
        $x_2_3 = {00 00 01 a2 14 14 14 28 ?? 00 00 0a 28 ?? 00 00 0a 6f ?? ?? 00 0a 0b 00 18 8d ?? 00 00 01 25 17 16 8d}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_AveMariaRAT_D_2147837528_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/AveMariaRAT.D!MTB"
        threat_id = "2147837528"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMariaRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {02 03 5d 0c 08 0a}  //weight: 2, accuracy: High
        $x_2_2 = {0e 04 0b 07 17 2e 05}  //weight: 2, accuracy: High
        $x_2_3 = {00 00 04 0c 08 74 ?? 00 00 1b 25 06 93 0b 06 18 58 93 07 61 0b}  //weight: 2, accuracy: Low
        $x_2_4 = {00 00 01 11 05 11 0a ?? ?? 00 00 1b 11 0c 11 07 58 11 09 59 93 61 11 0b ?? ?? 00 00 1b 11 09 11 0c 58 1f 11 58 11 08 5d 93 61 d1 6f ?? 00 00 0a 26 ?? 13 0e 38 ?? fe ff ff 11 09 17 58 13 09 ?? 13 0e 38}  //weight: 2, accuracy: Low
        $x_1_5 = "set_Timeout" ascii //weight: 1
        $x_1_6 = "HttpWebRequest" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

