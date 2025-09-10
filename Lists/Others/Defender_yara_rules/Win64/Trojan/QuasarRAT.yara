rule Trojan_Win64_QuasarRAT_A_2147842674_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/QuasarRAT.A!MTB"
        threat_id = "2147842674"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "QuasarRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {48 89 d9 48 89 c3 31 c0 e8 ?? ?? fa ff 48 89 44 24 68 48 89 4c 24 38 48 89 c7 48 89 de 49 89 c8 e8 ?? ?? fe ff 48 8b 54 24 38 48 39 d0 0f}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_QuasarRAT_D_2147851341_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/QuasarRAT.D!MTB"
        threat_id = "2147851341"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "QuasarRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "main.CrysisExperimental" ascii //weight: 2
        $x_2_2 = "main.DCRYSIS" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_QuasarRAT_E_2147901134_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/QuasarRAT.E!MTB"
        threat_id = "2147901134"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "QuasarRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {4d 89 63 18 48 8d 15 64 22 00 00 45 33 e4 4d 89 73 d8 48 8b f1 4c 89 65 0f 45 33 c9 4c 89 65 17 45 33 c0 44 89 65 1f 48 8d 4d 0f 44 89 65 23 44 89 65 0b 45 8b f4 45 8b fc 44 89 65 07 bf 01 00 00 00 ff 15}  //weight: 2, accuracy: High
        $x_2_2 = {48 8b 46 20 48 8d 55 17 44 8b 4d 0b 4d 8b c6 48 8b 4d 0f 44 89 64 24 30 c7 44 24 28 20 00 00 00 48 89 44 24 20 ff 15}  //weight: 2, accuracy: High
        $x_2_3 = {44 8b 46 18 48 8d 45 07 48 8b 56 10 45 33 c9 48 8b 4d 17 89 7c 24 48 48 89 44 24 40 48 8b 46 28 44 89 64 24 38 4c 89 64 24 30 c7 44 24 28 10 00 00 00 48 89 44 24 20 ff 15}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_QuasarRAT_DA_2147907653_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/QuasarRAT.DA!MTB"
        threat_id = "2147907653"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "QuasarRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "27"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = "**PIZZA TOWER ** New Client," ascii //weight: 20
        $x_1_2 = {2f 2f 63 64 6e 2e 64 69 73 63 6f 72 64 61 70 70 2e 63 6f 6d 2f 61 74 74 61 63 68 6d 65 6e 74 73 2f [0-100] 2f [0-15] 2e 62 61 74 [0-100] 26 43 4f 4d 50 55 54 45 52 4e 41 4d 45}  //weight: 1, accuracy: Low
        $x_1_3 = "//discord.com/api/webhooks/" ascii //weight: 1
        $x_1_4 = "getsockname" ascii //weight: 1
        $x_1_5 = "getpeername" ascii //weight: 1
        $x_1_6 = "getsockopt" ascii //weight: 1
        $x_1_7 = "setsockopt" ascii //weight: 1
        $x_1_8 = "closesocket" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_QuasarRAT_PAEY_2147914395_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/QuasarRAT.PAEY!MTB"
        threat_id = "2147914395"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "QuasarRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AntiReverseTest\\AntiReverse" ascii //weight: 1
        $x_1_2 = "start /b PowerShell.exe /c $process = Start-Process -FilePath" ascii //weight: 1
        $x_1_3 = "-WindowStyle Hidden -PassThru" ascii //weight: 1
        $x_1_4 = "SOFTWARE\\Wow6432Node\\Microsoft\\VisualStudio\\14.0\\Setup\\VC" wide //weight: 1
        $x_1_5 = "tempting to start ssvchost.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_QuasarRAT_GZF_2147945773_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/QuasarRAT.GZF!MTB"
        threat_id = "2147945773"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "QuasarRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {4c 03 f5 45 8b 66 ?? 45 8b 6e ?? 4c 03 e5 41 8b 46 ?? 4c 03 ed 48 03 c5 48 89 44 24 ?? 41 39 7e ?? ?? ?? 66 66 0f 1f 84 00 00 00 00 00 41 8b 0c bc 48 8d 15 ?? ?? ?? ?? 48 03 cd 41 b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 85 c0 0f 84 ?? ?? ?? ?? ff c7 41 3b 7e 18}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_QuasarRAT_GVA_2147951901_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/QuasarRAT.GVA!MTB"
        threat_id = "2147951901"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "QuasarRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 f8 8b 7c 24 34 0f b6 14 17 31 d0 89 fa 8b 7c 24 3c 88 04 37 46 89 f8 39 ee 7d 1a 0f b6 3c 33 85 c9 0f 84 38 01 00 00 89 f0 99 f7 f9 39 d1 77 cf}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

