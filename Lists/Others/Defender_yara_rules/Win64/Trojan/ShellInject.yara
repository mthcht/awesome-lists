rule Trojan_Win64_ShellInject_DB_2147942061_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellInject.DB!MTB"
        threat_id = "2147942061"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "ShellcodeLoader" ascii //weight: 10
        $x_10_2 = "YwAYwAonvsgHUbnoYwAonvsgHUbnnvsgHUbn" ascii //weight: 10
        $x_1_3 = "smartscreen" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellInject_DC_2147962221_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellInject.DC!MTB"
        threat_id = "2147962221"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4c 8b 4d f8 48 8d 4d e0 4c 8b 45 e0 45 33 e4 49 83 f9 0f 48 8b c3 49 0f 47 c8 33 d2 49 f7 f6 8a 04 0a 42 30 04 3b 49 83 f9 0f 76}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellInject_DD_2147962222_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellInject.DD!MTB"
        threat_id = "2147962222"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b d0 41 88 48 0d 4c 8b c3 0f b6 4f 0f 32 0f 48 83 38 0f 76 [0-4] 4c 8b 03 41 88 48 0e 48 8b cb 0f b6 47 10 32 07 48 83 3a 0f 76}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

