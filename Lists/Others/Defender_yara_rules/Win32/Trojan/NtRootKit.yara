rule Trojan_Win32_NtRootKit_A_2147850685_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NtRootKit.A!MTB"
        threat_id = "2147850685"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NtRootKit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {55 8b ec 53 c1 e0 ?? 8b 5d 08 c1 e3 ?? 0b c3 03 d2 03 d2 0b c2 0b c1}  //weight: 2, accuracy: Low
        $x_2_2 = "MyPspaddress is:" ascii //weight: 2
        $x_2_3 = "Driver Unload" ascii //weight: 2
        $x_2_4 = "PID is:" ascii //weight: 2
        $x_2_5 = "Create Device Success" ascii //weight: 2
        $x_2_6 = "Create SymbolicLink Success" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

