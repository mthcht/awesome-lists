rule Trojan_Win32_Dllhijack_GCM_2147928784_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dllhijack.GCM!MTB"
        threat_id = "2147928784"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dllhijack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {59 58 4a 30 54 32 ?? 45 5a 57 31 68 ?? 6d 51 2b 64 48 ?? 31 5a}  //weight: 10, accuracy: Low
        $x_1_2 = "KICA8L1JlZ2lzdHJhdGlvbkluZm8" ascii //weight: 1
        $x_1_3 = "Windows\\IOVAS" ascii //weight: 1
        $x_1_4 = "cmd.exe /B /c \"%s\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dllhijack_GCN_2147928896_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dllhijack.GCN!MTB"
        threat_id = "2147928896"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dllhijack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {56 57 53 55 83 ec ?? 8b 3d ?? ?? ?? ?? 64 a1 18 00 00 00 8b 40 30 8b 58 0c 83 c3 0c 8b 13 3b d3 ?? ?? 33 ed 8b 72 ?? 8b cd 0f b7 06 85 c0}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

