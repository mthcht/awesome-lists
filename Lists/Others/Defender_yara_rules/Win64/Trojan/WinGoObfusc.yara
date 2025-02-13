rule Trojan_Win64_WinGoObfusc_LK_2147841078_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/WinGoObfusc.LK!MTB"
        threat_id = "2147841078"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "WinGoObfusc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {44 0f b6 44 0c 77 44 0f b6 4c 0c 5e 45 29 c1 44 88 4c 0c 5e 48 ff c1 48 83 f9 19 7c e3}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_WinGoObfusc_TB_2147843830_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/WinGoObfusc.TB!MTB"
        threat_id = "2147843830"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "WinGoObfusc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {44 89 6c 24 28 8b 54 24 20 c1 ea 18 0f b6 d2 41 8b 14 97 42 33 54 a0 08 41 c1 ed 08 8b 7c 24 14 44 0f b6 cf 8b 5c 24 1c c1 eb 10 45 0f b6 ed 0f b6 db 33 14 9e 43 33 14 a8 43 33 14 8a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_WinGoObfusc_UX_2147850770_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/WinGoObfusc.UX!MTB"
        threat_id = "2147850770"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "WinGoObfusc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 07 48 ff c7 08 c0 74 d7 48 89 f9 48 89 fa ff c8 f2 ae 48 89 e9 ff 15 2e 01 00 00 48 09 c0 74 09 48 89 03 48 83 c3 08}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_WinGoObfusc_RN_2147850771_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/WinGoObfusc.RN!MTB"
        threat_id = "2147850771"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "WinGoObfusc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8b 2d 0b 08 00 00 48 8d be 00 f0 ff ff bb 00 10 00 00 50 49 89 e1 41 b8 04 00 00 00 48 89 da 48 89 f9 48 83 ec 20 ff d5 48 8d 87 af 01 00 00 80 20 7f 80 60 28 7f 4c 8d 4c 24 20 4d 8b 01 48 89 da 48 89 f9 ff d5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_WinGoObfusc_MK_2147901380_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/WinGoObfusc.MK!MTB"
        threat_id = "2147901380"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "WinGoObfusc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {49 ff c3 8b 5c 24 20 c1 eb 18 0f b6 db 45 8b 0c 9f 46 33 4c a0 0c c1 ef 08 8b 5c 24 10 0f b6 db 44 8b 6c 24 28 41 c1 ed 10 40 0f b6 ff 45 0f b6 ed 46 33 0c ae 45 33 0c b8 45 33 0c 9a 49 8d 5c 24 04 48 8b 7c 24 30}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

