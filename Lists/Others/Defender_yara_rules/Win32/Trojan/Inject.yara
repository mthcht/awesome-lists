rule Trojan_Win32_Inject_J_2147595766_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Inject.J"
        threat_id = "2147595766"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Inject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6c 6f 61 64 00 00 00 00 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 57 69 6e 64 6f 77 73}  //weight: 1, accuracy: High
        $x_1_2 = {25 73 25 73 25 73 00 00 5c 00 00 00 [0-16] 2e 65 78 65 00}  //weight: 1, accuracy: Low
        $x_1_3 = "Accept-Language: zh-cn" ascii //weight: 1
        $x_1_4 = {66 78 68 65 6c 6c 6f 2e 63 66 67 00 2f 6e 63 [0-3] 2f 6d 61 69 6c 2f 61 64 6d 69 6e 49 6e 66 6f 2e 61 73 70}  //weight: 1, accuracy: Low
        $x_1_5 = "MAC=%s&IP=%s&NAME=%s&OS=%s&LANG=%s" ascii //weight: 1
        $x_1_6 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Hotfix\\Q246009" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Inject_T_2147622040_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Inject.T"
        threat_id = "2147622040"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Inject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {80 3c 1e 66 75 29 80 7c 1e 01 24 75 22 80 7c 1e 02 47 75 1b 80 7c 1e 03 36}  //weight: 3, accuracy: High
        $x_1_2 = {0f b6 54 3a ff 33 55 f8 e8 ?? ?? ff ff 8b 55 f0 8b c6 e8 ?? ?? ff ff 47 4b 75 df}  //weight: 1, accuracy: Low
        $x_1_3 = {80 ea 0d e8 ?? ?? ff ff 8b 55 f4 8b c6 e8 ?? ?? ff ff 47 8b 45 fc e8 ?? ?? ff ff 3b f8 7e c5}  //weight: 1, accuracy: Low
        $x_1_4 = {eb 04 43 48 75 cd 85 ff 0f ?? ?? 01 00 00 e8 ?? ?? ff ff 84 c0 75 07 33 c0 e8 ?? ?? ff ff 6a 00 6a 00 57}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Inject_V_2147625288_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Inject.V"
        threat_id = "2147625288"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Inject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff e0 90 41 42 43 44 45 46 47 48 49 4a 4b 4c 4d 4e 4f 50 51 52 53 54 55 56 57 58 59 5a}  //weight: 1, accuracy: High
        $x_1_2 = {30 03 43 81 fb 9c 59 00 01 75 (f2|f3) e8 ?? ?? ff ff eb 0a}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 00 8b f0 85 f6 7e 1c bb 01 00 00 00 8b c5 e8 ?? ?? ff ff 0f b6 14 24 32 54 1f ff 88 54 18 ff 43 4e 75 e9 5a 5d 5f 5e 5b c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Inject_AK_2147650412_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Inject.AK"
        threat_id = "2147650412"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Inject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = "\\inject\\release\\" ascii //weight: 5
        $x_3_2 = "winmm64.dll" ascii //weight: 3
        $x_3_3 = "%s\\KB%d.log" ascii //weight: 3
        $x_1_4 = "\\Notify\\Winlogon" ascii //weight: 1
        $x_1_5 = "\\ShellServiceObjectDelayLoad" ascii //weight: 1
        $x_1_6 = {45 54 20 2f ?? 2e 70 68 70 3f}  //weight: 1, accuracy: Low
        $x_1_7 = "ost: www.google." ascii //weight: 1
        $x_1_8 = "ost: www.bing." ascii //weight: 1
        $x_1_9 = "firefox.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*) and 6 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 4 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Inject_AL_2147650882_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Inject.AL"
        threat_id = "2147650882"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Inject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 40 68 00 10 00 00 05 2a 01 00 00 50 6a 00 57 ff 15 ?? ?? ?? ?? 8b f0 85 f6 74 ?? 8b 1d ?? ?? ?? ?? 8d 54 24 10 52 68 29 01 00 00 68}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 40 68 00 10 00 00 05 2a 01 00 00 50 6a 00 ff 75 ?? ff 15 ?? ?? ?? ?? 89 45 ?? 85 c0 74 ?? 56 8b 35 ?? ?? ?? ?? 8d 4d ?? 51 68 29 01 00 00 68}  //weight: 1, accuracy: Low
        $x_1_3 = "/ajax.php" ascii //weight: 1
        $x_1_4 = "bn_mail" ascii //weight: 1
        $x_1_5 = "dao7erms_" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_Inject_ZH_2147712308_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Inject.ZH!bit"
        threat_id = "2147712308"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Inject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff 8a 8c 15 ?? ?? ?? ?? 8b 9d 70 ?? ?? ?? 8b 85 e0 ?? ?? ?? 30 0c 03}  //weight: 1, accuracy: Low
        $x_1_2 = {ff 8a 8c 15 ?? ?? ?? ?? 8b 9d ?? ?? ?? ?? 8b 03 8b 95 b0 ?? ?? ?? 30 0c 10}  //weight: 1, accuracy: Low
        $x_1_3 = {8a 04 11 8b 95 ?? ?? ?? ?? 8b 8d ?? ?? ?? ?? 30 04 0a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Inject_ZI_2147712309_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Inject.ZI!bit"
        threat_id = "2147712309"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Inject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 f8 89 45 ?? 8b 4d ?? 03 4d ?? 8b 55 ?? 03 55 ?? 8a 02 88 01 8b 4d ?? 83 c1 01 89 ?? ?? eb cc}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 02 89 45 fc 8b 8d ?? ?? ?? ?? 89 4d ?? 8b 55 ?? 8b 02 33 85 ?? ?? ?? ?? 8b 4d ?? 89 01}  //weight: 1, accuracy: Low
        $x_1_3 = {8b c9 ff e0 34 00 0f 85 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 51 8b 15 ?? ?? ?? ?? 52 e8 ?? ?? ?? ?? 83 c4 08 a1 ?? ?? ?? ?? 05 f0 1b 1b 00 a3 ?? ?? ?? ?? 8b ff b8 b0 18 5c 00 8b ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Inject_ZG_2147712310_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Inject.ZG!bit"
        threat_id = "2147712310"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Inject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 1c 01 8a 92 ?? ?? ?? ?? 32 da 88 1c 01}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 18 8a 4c ?? ?? 02 d9 88 18}  //weight: 1, accuracy: Low
        $x_1_3 = {8a 18 8b 74 ?? ?? 8a 8a ?? ?? ?? ?? 32 d9 46 85 d2 88 18}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Inject_LO_2147754551_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Inject.LO!MTB"
        threat_id = "2147754551"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Inject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 01 41 84 c0 75 ?? 2b ca 8b c6 33 d2 f7 f1 46 8a 82 ?? ?? ?? 00 30 44 3e ff 3b f3 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Inject_CA_2147811423_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Inject.CA!MTB"
        threat_id = "2147811423"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Inject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d0 88 55 [0-4] 8b 4d [0-4] 03 4d [0-4] 8b 55 [0-4] 83 ea [0-4] 33 ca 66 89 4d}  //weight: 1, accuracy: Low
        $x_1_2 = {03 d0 33 55 [0-4] 66 89 95 [0-4] eb 2a}  //weight: 1, accuracy: Low
        $x_1_3 = "VirtualAlloc" ascii //weight: 1
        $x_1_4 = "VirtualProtect" ascii //weight: 1
        $x_1_5 = "IsDebuggerPresent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Inject_L_2147835479_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Inject.L!MSR"
        threat_id = "2147835479"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Inject"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PIkO4y79T1leKsy4fiQcDIIsU2i3xIhR" ascii //weight: 1
        $x_1_2 = "ProcessInjection" ascii //weight: 1
        $x_1_3 = "ShellcodeDelegate" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

