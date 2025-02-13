rule Trojan_Win32_Johnnie_PA_2147743167_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Johnnie.PA!MTB"
        threat_id = "2147743167"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Johnnie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b ce c1 f9 1f 8b d1 33 c8 33 d7 3b ca 7f ?? 8b 4d ?? 8b 09 8b 51 0c 8b 79 14 2b d7 8a c8 80 e1 ?? 8d 3c 02 8a 14 02 32 ca 32 cb 03 c6 88 0f eb}  //weight: 1, accuracy: Low
        $x_1_2 = {8b ce c1 f9 1f 8b d1 33 c8 33 d7 3b ca 7f ?? 8b 4d ?? 8b 09 8b 51 0c 8b 79 14 2b d7 8a 0c 02 8d 3c 02 32 c8 32 cb 03 c6 88 0f eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Johnnie_OJ_2147754345_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Johnnie.OJ!MTB"
        threat_id = "2147754345"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Johnnie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {34 f9 be e9 3b 41 00 bb ?? ?? ?? ?? 88 07 2b f7 2b df 8d 4b ?? 02 ca 32 0c 16 2a 0a 80 f1 ?? c0 c9 ?? 32 0a 88 4a 01 4a 8d 04 13 83 f8 ?? 7d e2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Johnnie_ER_2147754738_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Johnnie.ER!MTB"
        threat_id = "2147754738"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Johnnie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 80 83 c0 01 89 45 80 8b 4d f4 83 e9 01 39 4d 80 ?? ?? 8b 55 f4 83 ea 01 2b 55 80 8b 45 f8 0f be 0c 10 f7 d1 8b 55 84 03 55 80 88 0a eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Johnnie_A_2147754903_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Johnnie.A!MTB"
        threat_id = "2147754903"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Johnnie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "LoginCookie name=" ascii //weight: 1
        $x_1_2 = "/scookiestxt" ascii //weight: 1
        $x_10_3 = "http://hfuie32.2ihsfa.com/" ascii //weight: 10
        $x_1_4 = "manager/account_settings/account_billing" wide //weight: 1
        $x_1_5 = "autoLoginCookie name=" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Johnnie_LM_2147755550_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Johnnie.LM!MTB"
        threat_id = "2147755550"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Johnnie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 9b 00 00 00 00 8a 91 ?? ?? ?? ?? 30 ?? ?? ?? ?? ?? 83 f9 ?? 75 ?? 33 c9 eb ?? 41 40 3b c6 72 ?? 8b 45 fc ff ?? 6a 00 ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Johnnie_LM_2147755550_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Johnnie.LM!MTB"
        threat_id = "2147755550"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Johnnie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d a4 24 00 [0-48] 8a 91 ?? ?? ?? ?? 30 ?? ?? ?? ?? ?? 83 f9 ?? 75 ?? 33 c9 eb ?? 41 40 3b c6 72 ?? 8d 45 ?? 50 6a ?? 56 68 ?? ?? ?? ?? ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Johnnie_B_2147758874_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Johnnie.B!MTB"
        threat_id = "2147758874"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Johnnie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\Microsoft\\OfficeUpdate" wide //weight: 1
        $x_1_2 = "-ExecutionPolicy ByPass -WindowStyle Hidden -Encoded" wide //weight: 1
        $x_3_3 = "WrapperPowershell\\Release\\WrapperStub.pdb" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Johnnie_GNE_2147924731_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Johnnie.GNE!MTB"
        threat_id = "2147924731"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Johnnie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {40 00 f1 4f 40 00 00 50 40 00 17 50 40 00 57 ?? 40 00 66 ?? 40}  //weight: 5, accuracy: Low
        $x_5_2 = {53 40 00 11 54 40 00 5c 54 ?? 00 e2 54 40 00 51 ?? 40 00 f4 55 40 00 04 56 40 00 06}  //weight: 5, accuracy: Low
        $x_1_3 = "deinfecter" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

