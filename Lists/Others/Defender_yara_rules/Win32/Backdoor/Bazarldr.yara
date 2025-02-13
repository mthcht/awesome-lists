rule Backdoor_Win32_Bazarldr_AB_2147775810_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Bazarldr.AB!MTB"
        threat_id = "2147775810"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Bazarldr"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 04 0f 88 04 0e 33 c0 88 1c 0f 8a 04 0e 03 c2 33 d2 f7 35 ?? ?? ?? ?? 8b 44 24 ?? 8a 1c 28 8a 14 0a 32 da 88 ?? 28 8b 44 24 1c 45}  //weight: 1, accuracy: Low
        $x_1_2 = "CLSID\\%1\\LocalServer32" ascii //weight: 1
        $x_1_3 = "Microsoft Visual C++ Runtime" ascii //weight: 1
        $x_1_4 = "VirtualAllocExNuma" ascii //weight: 1
        $x_1_5 = "All files (*.*)|*.*||" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Bazarldr_AC_2147775811_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Bazarldr.AC!MTB"
        threat_id = "2147775811"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Bazarldr"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 34 17 89 d1 31 d2 01 f3 89 d8 f7 f5 0f b6 04 17 89 d3 89 f2 88 04 0f 88 14 1f 31 d2 0f b6 04 0f 01 f0 f7 f5 0f b6 04 17 8b 54 24 ?? 30 02 8b 04 24}  //weight: 1, accuracy: Low
        $x_1_2 = "DllRegisterServer" ascii //weight: 1
        $x_1_3 = "DllGetClassObject" ascii //weight: 1
        $x_1_4 = "DllCanUnloadNow" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Bazarldr_DA_2147776085_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Bazarldr.DA!MTB"
        threat_id = "2147776085"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Bazarldr"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "C:\\WINDOWS\\system32\\cmd.exe /c pause" ascii //weight: 5
        $x_5_2 = "ascvcevtrhyhjtjkuybeavr" ascii //weight: 5
        $x_1_3 = "console_hello" ascii //weight: 1
        $x_1_4 = "AcquireSRWLockExclusive" ascii //weight: 1
        $x_1_5 = "connection already in progress" ascii //weight: 1
        $x_1_6 = "string too long" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Bazarldr_AD_2147776130_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Bazarldr.AD!MTB"
        threat_id = "2147776130"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Bazarldr"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {be 08 0f b6 55 ?? 33 ca a1 ?? ?? ?? ?? 03 45 ?? 88 08 e9 13 00 41 8a 89 ?? ?? ?? ?? 88 4d ?? a1 ?? ?? ?? ?? 03 45 ?? 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

