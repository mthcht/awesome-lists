rule Trojan_Win32_ThemidaPacked_D_2147788920_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ThemidaPacked.D!MTB"
        threat_id = "2147788920"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ThemidaPacked"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {32 47 29 a9 bf 52 ae 03 c0 81 9e 4f 43 3e 93 d3 34 2e 04 7a e4 56 22 87 4b 03 00 44 97}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ThemidaPacked_PK_2147797874_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ThemidaPacked.PK!MTB"
        threat_id = "2147797874"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ThemidaPacked"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {86 0b 10 74 b2 15 08 72 aa 13 1c d7 31 15 02 d4 84 0b 4f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ThemidaPacked_RT_2147799503_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ThemidaPacked.RT!MTB"
        threat_id = "2147799503"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ThemidaPacked"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".themida" ascii //weight: 1
        $x_1_2 = "MBOVKTkv:4a" ascii //weight: 1
        $x_1_3 = "K_OUT r=0%dcWLS" ascii //weight: 1
        $x_1_4 = "oftware~" ascii //weight: 1
        $x_1_5 = "*/che0kpront" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

