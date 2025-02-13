rule Trojan_Win32_Yakes_RL_2147744239_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Yakes.RL!MTB"
        threat_id = "2147744239"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Yakes"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f b7 ce 8a 14 0a 32 10 46 88 14 39 66 3b 70 ?? 72 20 00 8b 50}  //weight: 2, accuracy: Low
        $x_2_2 = {0f 95 c1 57 49 23 c8 03 c8 81 c9 ?? ?? ?? ?? 51 57 57 57 ff 75 ?? 89 4d ?? ff 75 ?? ff 75 ?? ff 15 42 00 80 7d ?? ?? b8}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Yakes_DSK_2147748659_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Yakes.DSK!MTB"
        threat_id = "2147748659"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Yakes"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f b6 d0 0f b6 f1 0f af d6 a0 ?? ?? ?? ?? 88 d1 0f b6 d0 88 0c 15 ?? ?? ?? ?? a0 ?? ?? ?? ?? 04 01 a2 ?? ?? ?? ?? eb 0b 00 a0 ?? ?? ?? ?? 8a 0d}  //weight: 2, accuracy: Low
        $x_1_2 = {83 c4 08 8b 15 ?? ?? ?? ?? 83 c2 04 89 15 ?? ?? ?? ?? b8 6f 00 00 00 85 c0 0f 85}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 08 33 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 89 0a 8b e5 5d c3 05 00 a1}  //weight: 1, accuracy: Low
        $x_2_4 = {03 c2 89 85 ?? fd ff ff 8b 8d ?? fc ff ff 0f af 4d 10 6b c9 28 89 8d 14 00 0f b7 05 ?? ?? ?? ?? 0f af 85 ?? fd ff ff 03 85 ?? fd ff ff}  //weight: 2, accuracy: Low
        $x_2_5 = {0f b6 32 88 d9 d3 fe 89 75 fc 8a 4d fc 88 08 88 f9 88 d8 d2 e0 00 c7 88 3a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Yakes_DSP_2147754593_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Yakes.DSP!MTB"
        threat_id = "2147754593"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Yakes"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {81 c1 34 d4 00 00 89 8d ?? ?? ff ff 8b 55 f8 8b 02 33 85 ?? ?? ff ff 8b 4d f8 89 01 06 00 8b 0d}  //weight: 2, accuracy: Low
        $x_2_2 = {8b 45 f8 33 45 f0 89 45 f8 c7 85 ?? fc ff ff 8d 00 00 00 8b 0d ?? ?? ?? ?? 8b 55 f8 89 11}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Yakes_CC_2147811149_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Yakes.CC!MTB"
        threat_id = "2147811149"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Yakes"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {32 44 24 53 8b 15 ?? ?? ?? ?? 6a 00 52 88 44 24}  //weight: 1, accuracy: Low
        $x_1_2 = {8b d6 83 f2 03 69 d2 [0-4] 2b d0 89 54 24}  //weight: 1, accuracy: Low
        $x_1_3 = "QueryPerformanceCounter" ascii //weight: 1
        $x_1_4 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_5 = "GetTickCount" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Yakes_GER_2147841810_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Yakes.GER!MTB"
        threat_id = "2147841810"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Yakes"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "rundll32.exe %sadvpack.dll,DelNodeRunDLL32" ascii //weight: 1
        $x_1_2 = "rundll32.exe %s,InstallHinfSection %s 128 %s" ascii //weight: 1
        $x_1_3 = "cmd /c i.bat" ascii //weight: 1
        $x_1_4 = "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" ascii //weight: 1
        $x_1_5 = "curl -L -o d.exe il2d.cc" ascii //weight: 1
        $x_1_6 = "wextract_cleanup%d" ascii //weight: 1
        $x_1_7 = "Command.com /c %s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Yakes_ASG_2147894259_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Yakes.ASG!MTB"
        threat_id = "2147894259"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Yakes"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {d8 e6 6e 24 d0 ee 18 0e 5e 05 1c 9d ba 7a 5d de 9c 2f c0 42 c6 a3 9d 14 2c 4e e8 82 60 f3 76 d2 5a 5c ee 64 fe b8 a3 dd fc af d6 e5 25 2c f4 65 d3 ab 18 77 84 db 05 51 0c 0d dc 33 0e}  //weight: 2, accuracy: High
        $x_2_2 = {94 e3 39 8c 2e 16 02 60 93 48 9e 95 19 01 f7 7c e4 ef 50 e2 43 31 25 de fb c4 85 be c2 04 fe 3d a2 be 85 aa ef c9 02 39 a2 f4 ba 65 46 30 39 e8 fb 72 4d 5f e7 02 d4 07 bf 67 ff 5c 10 4c 1b 40}  //weight: 2, accuracy: High
        $x_1_3 = {40 08 00 00 50 3c 00 00 00 00 00 00 30 81 00 00 10 00 00 00 50 08 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Yakes_SPPB_2147913474_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Yakes.SPPB!MTB"
        threat_id = "2147913474"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Yakes"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c6 33 c2 33 45 70 c7 05 ?? ?? ?? ?? ee 3d ea f4 2b c8 89 45 6c 8b c1 c1 e0 04 89 45 70 8b 85 ?? ?? ?? ?? 01 45 70 8b 55 74 8b c1 c1 e8 05 03 d1 89 45 6c 8b 85 ?? ?? ?? ?? 01 45 6c 8b 45 6c 33 c2 31 45 70 8b 45 70 29 45 68}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Yakes_SPON_2147914161_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Yakes.SPON!MTB"
        threat_id = "2147914161"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Yakes"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff 50 89 b5 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8a 85 ?? ?? ?? ?? 30 04 3b 83 7d 08 0f 59 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

