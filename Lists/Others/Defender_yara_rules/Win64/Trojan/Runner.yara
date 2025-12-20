rule Trojan_Win64_Runner_EC_2147850519_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Runner.EC!MTB"
        threat_id = "2147850519"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Runner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {0f ba f1 1f 49 03 c9 8b 44 11 14 0f ba f0 1f 49 03 c1 8b 34 10 8b 6c 10 04 48 03 f2 74 c8}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Runner_MB_2147911089_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Runner.MB!MTB"
        threat_id = "2147911089"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Runner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "D3Ext/Hooka" ascii //weight: 1
        $x_1_2 = "Shellcode should have been executed!" ascii //weight: 1
        $x_1_3 = "binject" ascii //weight: 1
        $x_1_4 = "SuppaDuppa" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Runner_MK_2147956577_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Runner.MK!MTB"
        threat_id = "2147956577"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Runner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_15_1 = {41 b8 68 00 00 00 33 d2 48 8d 8d b0 39 00 00 ?? ?? ?? ?? ?? 90 41 b8 18 00 00 00 33 d2 48 8d 8d 38 3a}  //weight: 15, accuracy: Low
        $x_10_2 = {48 8b 85 68 39 00 00 48 ff c0 4c 8d 85 50 19 00 00 48 8b d0 48 8b 8d 88 39}  //weight: 10, accuracy: High
        $x_5_3 = "ping -n 11 127.0.0.1" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Runner_AHB_2147958257_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Runner.AHB!MTB"
        threat_id = "2147958257"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Runner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "70"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = "RANDOM_COMMENT_" ascii //weight: 20
        $x_40_2 = "start /b KMSELDI..exe >nul 2>&1 & ping -n 11 127.0.0.1 >nul 2>&1 & unrar x -o+ -pdialog \"dialog.rar" ascii //weight: 40
        $x_10_3 = {66 89 01 48 8d 85 ?? ?? ?? ?? 48 8b f8 33 c0 b9 ?? ?? ?? ?? f3 aa 4c 8d 4d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Runner_AMTB_2147959841_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Runner!AMTB"
        threat_id = "2147959841"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Runner"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "document\\_\\_\\_\\document.bat" ascii //weight: 2
        $x_2_2 = "document\\_\\_\\_" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

