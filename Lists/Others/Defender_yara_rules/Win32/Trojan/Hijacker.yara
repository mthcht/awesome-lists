rule Trojan_Win32_Hijacker_RPY_2147847560_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Hijacker.RPY!MTB"
        threat_id = "2147847560"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Hijacker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 7d d8 6a 40 68 00 30 00 00 ff 77 50 ff 76 08 ff 33 ff 15}  //weight: 1, accuracy: High
        $x_1_2 = {53 56 33 c0 c7 06 44 00 00 00 50 50 6a 04 50 50 50 57 50 c7 46 2c 01 00 00 00 66 89 46 30 ff 15}  //weight: 1, accuracy: High
        $x_1_3 = "NtQueryInformationProcess" ascii //weight: 1
        $x_1_4 = "NtUnmapViewOfSection" ascii //weight: 1
        $x_1_5 = "HOLLOWING.pdb" ascii //weight: 1
        $x_1_6 = "ReadProcessMemory" ascii //weight: 1
        $x_1_7 = "WriteProcessMemory" ascii //weight: 1
        $x_1_8 = "ResumeThread" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Hijacker_ARA_2147925941_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Hijacker.ARA!MTB"
        threat_id = "2147925941"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Hijacker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a 17 80 ea 41 8a 4f 01 80 e9 41 c1 e1 04 02 d1 88 10 80 ea 17 80 f2 17 80 c2 17 88 10 40 83 c7 02 4e 75 dc}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

