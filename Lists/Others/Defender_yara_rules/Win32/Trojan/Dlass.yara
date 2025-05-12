rule Trojan_Win32_Dlass_GQX_2147925907_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dlass.GQX!MTB"
        threat_id = "2147925907"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dlass"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 00 a2 0a 00 d5 56 85 48}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dlass_GPPA_2147929276_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dlass.GPPA!MTB"
        threat_id = "2147929276"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dlass"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 00 30 0a 00 2c 7c 5e 9c}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dlass_GPPB_2147929569_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dlass.GPPB!MTB"
        threat_id = "2147929569"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dlass"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4a e6 0c 00 36 e6 0c 00 26 e6 0c 00 16 e6 0c 00 08 e6 0c 00 f8 e5 0c 00 e6 e5 0c 00 d6 e5 0c 00 c6 e5 0c 00 b4 e5 0c 00 a6 e5 0c 00 5c e6 0c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dlass_GPPC_2147929570_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dlass.GPPC!MTB"
        threat_id = "2147929570"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dlass"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 00 68 0a 00 dd 20 30 ae 71 f7 48}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dlass_GPPD_2147929622_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dlass.GPPD!MTB"
        threat_id = "2147929622"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dlass"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {5a f1 0c 00 4c f1 0c 00 3a f1 0c 00 28 f1 0c 00 14 f1 0c 00 00 f1 0c 00 f0 f0 0c 00 d6 f0 0c 00 c8 f0 0c 00 ba f0 0c 00 aa f0 0c 00 9a f0 0c}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dlass_GPPE_2147941126_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dlass.GPPE!MTB"
        threat_id = "2147941126"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dlass"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 00 96 0a 00 59 bb ab 4d}  //weight: 4, accuracy: Low
        $x_4_2 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 00 96 0a 00 d7 7a e8 56}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

