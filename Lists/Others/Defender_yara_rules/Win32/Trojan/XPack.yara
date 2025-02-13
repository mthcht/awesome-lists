rule Trojan_Win32_XPack_CZZ_2147841194_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/XPack.CZZ!MTB"
        threat_id = "2147841194"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "XPack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8a 44 1e 04 8b d6 2b 55 f4 89 75 f4 83 f2 ?? 3c ?? 74}  //weight: 10, accuracy: Low
        $x_1_2 = "NEOxGetProcAddress" ascii //weight: 1
        $x_1_3 = "VirtualFree" ascii //weight: 1
        $x_1_4 = "VirtualAlloc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_XPack_NP_2147896919_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/XPack.NP!MTB"
        threat_id = "2147896919"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "XPack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {2b 0d be 33 4c 00 03 0d ?? ?? ?? ?? c1 e1 06 2b cb 81 f9 ?? ?? ?? ?? 73 06 03 0d ?? ?? ?? ?? c1 c9 02 29 0d ?? ?? ?? ?? 2b 0d 3f 32}  //weight: 5, accuracy: Low
        $x_1_2 = "xXxdxjx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_XPack_NP_2147896919_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/XPack.NP!MTB"
        threat_id = "2147896919"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "XPack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {29 c1 89 4c 24 ?? 8b 44 24 30 8b 4c 24 ?? 89 48 54 8b 44 24 ?? 8b 4c 24 30}  //weight: 3, accuracy: Low
        $x_3_2 = {83 c1 58 81 fa ?? ?? ?? ?? 89 44 24 18 89 4c 24 ?? 72 00 8b 44 24 14 8b 4c 24 ?? 89 08 8b 54 24}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_XPack_NC_2147897172_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/XPack.NC!MTB"
        threat_id = "2147897172"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "XPack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {74 23 38 78 bb 23 ad ?? ?? ?? ?? 20 b5 a4 21 1a 36 14 ?? 34 45 93 03 b8 1b 0c 15 81 09 1f 79 24}  //weight: 5, accuracy: Low
        $x_1_2 = "98te.4y" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

