rule Trojan_Win32_Miniduke_SPP_2147836052_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Miniduke.SPP!MTB"
        threat_id = "2147836052"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Miniduke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8b 4d f8 83 c1 01 89 4d f8 8b 55 f8 3b 55 d0 73 1f 8b 45 f0 03 45 f8 0f b6 08 0f b6 55 e7 03 55 f8 0f b6 c2 33 c8 8b 55 e0 03 55 f8 88 0a eb d0}  //weight: 5, accuracy: High
        $x_2_2 = "adobearm.tmp" ascii //weight: 2
        $x_2_3 = "AdobeTray.dll" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Miniduke_GHC_2147845727_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Miniduke.GHC!MTB"
        threat_id = "2147845727"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Miniduke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 45 08 0f b6 40 35 8b 4d 0c 0f b6 49 35 33 d2 3b c1 0f 9c c2 88 55 ff 8a 45 ff c9 c3}  //weight: 10, accuracy: High
        $x_1_2 = "Bqwertyuiopasdfghjklzxcvbnm" ascii //weight: 1
        $x_1_3 = "javacc.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Miniduke_GNI_2147851239_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Miniduke.GNI!MTB"
        threat_id = "2147851239"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Miniduke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {83 7d d8 10 8b 7d c4 73 03 8d 7d c4 8b 55 e8 8b c8 83 e1 03 03 c9 03 c9 03 c9 d3 ea 8b 4d d4 d1 e9 03 cf 32 14 01 40 88 54 30 ff 3d 00 00 20 00}  //weight: 10, accuracy: High
        $x_1_2 = "ClientUI.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

