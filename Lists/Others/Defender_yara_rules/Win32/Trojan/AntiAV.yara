rule Trojan_Win32_AntiAV_MR_2147753401_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AntiAV.MR!MTB"
        threat_id = "2147753401"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AntiAV"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c3 c1 e8 ?? 03 44 24 ?? 8d 3c 1e 33 cf c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 4c 24 ?? 81 fa ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
        $x_1_2 = {5f 5e 89 68 ?? 5d 89 18 5b 33 cc e8 ?? ?? ?? ?? 81 c4 ?? ?? ?? ?? c2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AntiAV_MS_2147753402_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AntiAV.MS!MTB"
        threat_id = "2147753402"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AntiAV"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d7 c1 ea ?? 03 cd 03 c7 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 33 c8 0f 57 c0 03 d6 [0-12] 81 3d [0-8] 89 4c 24 ?? 75}  //weight: 1, accuracy: Low
        $x_1_2 = {5f 5e 5d 89 ?? ?? ?? 33 cc e8 ?? ?? ?? ?? 81 c4 ?? ?? ?? ?? c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AntiAV_CA_2147812623_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AntiAV.CA!MTB"
        threat_id = "2147812623"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AntiAV"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff d7 ff d3 81 fe 12 80 5d 03 7f 15 46 8b c6 99 81 fa [0-4] 7c e8 7f 07 3d 2f 46 15 1f 72 df}  //weight: 1, accuracy: Low
        $x_1_2 = "VebtualProtect" ascii //weight: 1
        $x_1_3 = "VirtualAlloc" ascii //weight: 1
        $x_1_4 = "IsDebuggerPresent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AntiAV_BT_2147831373_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AntiAV.BT!MTB"
        threat_id = "2147831373"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AntiAV"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MAINICON.lnk" ascii //weight: 1
        $x_1_2 = "sys.key" wide //weight: 1
        $x_1_3 = "GFIRestart32.exe" wide //weight: 1
        $x_1_4 = "ZhuDongFangYu.exe" wide //weight: 1
        $x_1_5 = "Software\\Tencent\\Plugin\\VAS" ascii //weight: 1
        $x_1_6 = "[numlock]" wide //weight: 1
        $x_1_7 = "[ralt]" wide //weight: 1
        $x_1_8 = "[enter]" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AntiAV_SP_2147848125_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AntiAV.SP!MTB"
        threat_id = "2147848125"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AntiAV"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MLGBCAO." ascii //weight: 1
        $x_1_2 = "amdk8Device" ascii //weight: 1
        $x_1_3 = "ccte1sto" ascii //weight: 1
        $x_1_4 = "amdk8.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AntiAV_GNO_2147851492_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AntiAV.GNO!MTB"
        threat_id = "2147851492"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AntiAV"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b ec 83 ec ?? 80 65 fd 00 56 68 ?? ?? ?? ?? c6 45 f0 53 c6 45 f1 68 c6 45 f2 65 c6 45 f3 6c c6 45 f4 6c c6 45 f5 45 c6 45 f6 78 c6 45 f7 65 c6 45 f8 63 c6 45 f9 75 c6 45 fa 74 c6 45 fb 65 c6 45 fc 41 ff 15}  //weight: 10, accuracy: Low
        $x_10_2 = {c6 45 f8 6b c6 45 f9 69 c6 45 fa 6c c6 45 fb 6c c6 45 fc 68 c6 45 fd 79}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AntiAV_EAG_2147930127_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AntiAV.EAG!MTB"
        threat_id = "2147930127"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AntiAV"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {33 d7 33 d6 c7 05 ?? ?? ?? ?? ff ff ff ff 2b da 8b 44 24 28 29 44 24 10 83 6c 24 14 01}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AntiAV_EAUH_2147932053_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AntiAV.EAUH!MTB"
        threat_id = "2147932053"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AntiAV"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {33 c2 89 84 24 d0 02 00 00 89 2d ?? ?? ?? ?? 8b 84 24 d0 02 00 00 29 44 24 18 81 3d}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

