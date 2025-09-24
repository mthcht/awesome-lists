rule Trojan_Win32_ModiLoader_AMI_2147853253_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ModiLoader.AMI!MTB"
        threat_id = "2147853253"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ModiLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b f0 8b dc c6 03 63 c6 43 01 6d c6 43 02 64 c6 43 03 20 c6 43 04 2f c6 43 05 63 c6 43 06 20 c6 43 07 65 c6 43 08 72 c6 43 09 61 c6 43 0a 73 c6 43 0b 65 c6 43 0c 20 c6 43 0d 2f c6 43 0e 46 c6 43 0f 20 8b c6 8b d3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ModiLoader_AML_2147888189_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ModiLoader.AML!MTB"
        threat_id = "2147888189"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ModiLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 c0 10 86 c4 29 f8 80 eb e8 01 f0 89 07 83 c7 05 88 d8 e2 ?? 8d be 00 20 01 00 8b 07 09 c0 74 ?? 8b 5f 04 8d 84 30 14 4e 01 00 01 f3 50 83 c7 08 ff 96 a0 4e 01 00 95 8a 07 47 08 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ModiLoader_AMO_2147888921_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ModiLoader.AMO!MTB"
        threat_id = "2147888921"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ModiLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {85 c0 7e 1a 8a 93 a4 50 40 00 30 16 46 43 81 e3 07 00 00 80 79 05 4b 83 cb f8 43 48}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ModiLoader_AMR_2147889365_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ModiLoader.AMR!MTB"
        threat_id = "2147889365"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ModiLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d6 8b c3 ff 15 ?? ?? ?? ?? 84 db 75 0d e8 ?? ?? ?? ?? 8b 98 00 00 00 00 eb 0f 80 fb 18 77 0a 33 c0 8a c3 8a 98 38 30 00 10 33 c0 8a c3 8b d6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ModiLoader_AM_2147894743_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ModiLoader.AM!MTB"
        threat_id = "2147894743"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ModiLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8d 34 38 8b c1 83 c1 02 99 2b c2 8a 54 0e 08 d1 f8 81 f9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ModiLoader_AMBF_2147902385_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ModiLoader.AMBF!MTB"
        threat_id = "2147902385"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ModiLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 38 ff 57 0c 8b 85 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 0f b6 44 10 ff 0f b6 c0 33 d2 05 ?? ?? ?? ?? 83 d2 00 8b d0 8d 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ModiLoader_ML_2147904575_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ModiLoader.ML!MTB"
        threat_id = "2147904575"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ModiLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 15 e4 2b 61 00 42 8d 44 10 ff 50 a1 e4 2b 61 00 8a 04 07 5a 88 02 ff 05 e4 2b 61 00 4b 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ModiLoader_GA_2147906550_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ModiLoader.GA!MTB"
        threat_id = "2147906550"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ModiLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "responsetext" ascii //weight: 1
        $x_1_2 = "[InternetShortcut]" ascii //weight: 1
        $x_1_3 = "ECHO F|xcopy " ascii //weight: 1
        $x_1_4 = " /K /D /H /Y" ascii //weight: 1
        $x_1_5 = "C:\\Windows \\System32\\easinvoker.exe" ascii //weight: 1
        $x_1_6 = "KDECO.bat" ascii //weight: 1
        $x_1_7 = "ping 127.0.0.1 -n" ascii //weight: 1
        $x_1_8 = "start /min powershell.exe -inputformat none -outputformat none -NonInteractive -Command \"Add-MpPreference -ExclusionPath 'C:\\Users'\" & exit" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ModiLoader_HNA_2147907786_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ModiLoader.HNA!MTB"
        threat_id = "2147907786"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ModiLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 00 00 61 72 63 68 69 76 65 5f 77 72 69 74 65 5f 6f 70 65 6e 00 00 61 72 63 68 69 76 65 69 6e 74 00 00 ff ff ff ff}  //weight: 1, accuracy: High
        $x_1_2 = {48 6f 6f 6b 43 61 6c 6c 62 61 63 6b 00 00 00 00 ff ff ff ff 0a 00 00 00 4a 75 73 6d 65 40 5e 5e 5e 40 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {46 69 72 65 77 61 6c 6c 41 50 49 2e 00 00 00 00 49 63 66 49 73 50 6f 72 74 41 6c 6c 6f 77 65 64 00 00 00 00 44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72}  //weight: 1, accuracy: High
        $x_1_4 = {73 63 72 65 65 6e 70 73 00 00 00 00 44 6c 6c 47 65 74 43 6c 61 73 73 4f 62 6a 65 63 74 00 00 00 ff ff ff ff 05 00 00 00 73 6d 61 72 74}  //weight: 1, accuracy: High
        $x_1_5 = {00 42 43 72 79 70 74 00 00 ff ff ff ff 02 00 00 00 56 65 00 00 ff ff ff ff 02 00 00 00 72 69 00 00 ff ff ff ff 02 00 00 00 66 79 00 00 ff ff ff ff 02 00 00 00 ?? ?? 00}  //weight: 1, accuracy: Low
        $x_1_6 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 00 00 00 ff ff ff ff 03 00 00 00 65 61 6d 00 ff ff ff ff 08 00 00 00 73 63 72 65 65 6e 70 73 00 00 00 00 ff ff ff ff 05 00 00 00 73 6d 61 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_ModiLoader_ARA_2147909536_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ModiLoader.ARA!MTB"
        threat_id = "2147909536"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ModiLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "mkdir \"\\\\?\\C:\\Windows \\System32\"" ascii //weight: 2
        $x_2_2 = "ECHO F|xcopy" ascii //weight: 2
        $x_2_3 = "\"C:\\Windows \\System32\\\" /K /D /H /Y" ascii //weight: 2
        $x_2_4 = "\"easinvoker.exe\"" ascii //weight: 2
        $x_2_5 = "\"netutils.dll\"" ascii //weight: 2
        $x_2_6 = "\"KDECO.bat\"" ascii //weight: 2
        $x_2_7 = "\"Add-MpPreference -ExclusionPath 'C:\\Users'\"" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ModiLoader_BAA_2147935613_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ModiLoader.BAA!MTB"
        threat_id = "2147935613"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ModiLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {33 06 29 d8 2d ?? ?? ?? ?? 89 02 83 c6 04 41 8b c1 2b 45 18 0f 85 05}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

