rule Trojan_Win32_QBot_AR_2147751395_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/QBot.AR!MSR"
        threat_id = "2147751395"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "QBot"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Watchoh\\fightAnd\\Studentand\\casethird\\DirectHascamp.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_QBot_RPA_2147796005_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/QBot.RPA!MTB"
        threat_id = "2147796005"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "QBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {66 72 69 63 74 69 6f 6e 61 6c 6c 79 00 6d 61 6c 65 64 75 63 61 74 69 6f 6e 00 6d 6f 6c 6f 73 73 69 61 6e 00 6f 70 68 69 63 00 70 61 72 6b 69 6e 67}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_QBot_RPS_2147812915_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/QBot.RPS!MTB"
        threat_id = "2147812915"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "QBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {61 74 68 79 72 69 64 61 65 00 66 61 74 69 6c 00 66 65 6c 74 6d 6f 6e 67 65 72 00 66 6f 72 65 6d 69 73 67 69 76 69 6e 67 00 6a 75 6d 61 6e 61}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_QBot_RPB_2147813056_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/QBot.RPB!MTB"
        threat_id = "2147813056"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "QBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {72 76 79 6d 61 67 65 65 66 73 2e 64 6c 6c 00 61 69 70 69 6b 67 77 76 6c 69 78 63 63 00 61 70 76 61 68 72 7a 62 73 7a 6d 70 68 71 64 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_QBot_RPW_2147813883_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/QBot.RPW!MTB"
        threat_id = "2147813883"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "QBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {99 52 50 a1 b4 0e 47 00 33 d2 3b 54 24 04 75 0d 3b 04 24}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_QBot_RPZ_2147814098_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/QBot.RPZ!MTB"
        threat_id = "2147814098"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "QBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6a 00 e8 3e ce f5 ff 6a 00 e8 37 ce f5 ff 6a 00 e8 30 ce f5 ff 6a 00 e8 29 ce f5 ff 6a 00 e8 22 ce f5 ff 6a 00 e8 1b ce f5 ff 6a 00 e8 14 ce f5 ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_QBot_RPD_2147814101_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/QBot.RPD!MTB"
        threat_id = "2147814101"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "QBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 68 4b 67 54 52 6b 00 42 6b 74 66 4a 00 43 7a 4e 6b 74 45 00 44 41 4b 6b 45 4d 65 5a 66 00 44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_QBot_RPX_2147814577_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/QBot.RPX!MTB"
        threat_id = "2147814577"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "QBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {58 10 0c 5a 1c 71 62 09 1c 71 62 09 1c 71 62 09 61 08 be 09 6a 71 62 09 73 07 fc 09 18 71 62 09}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_QBot_RPO_2147837175_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/QBot.RPO!MTB"
        threat_id = "2147837175"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "QBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 7d 94 f3 a5 a4 6a 40 68 00 30 00 00 8b 45 0c 6b 08 03 51 6a 00 ff 15 ?? ?? ?? ?? 89 45 dc c7 45 ec 00 00 00 00 8b 55 0c 8b 02 89 45 e4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_QBot_CRIE_2147847125_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/QBot.CRIE!MTB"
        threat_id = "2147847125"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "QBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 00 89 c6 8b 4d e4 ba ?? ?? ?? ?? 89 c8 f7 ea c1 fa ?? 89 c8 c1 f8 ?? 29 c2 89 d0 c1 e0 ?? 01 d0 01 c0 29 c1 89 ca 0f b6 82 ?? ?? ?? ?? 31 f0 88 03 83 45 e4 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

