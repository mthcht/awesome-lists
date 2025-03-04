rule Trojan_Win32_LokiBot_SR_2147733255_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LokiBot.SR!MTB"
        threat_id = "2147733255"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 6a 00 6a 00 6a 00 6a 00 e8 ?? ?? ?? ?? 4b 75 ?? 6a 00 6a 00 6a 00 6a 00 6a 00 e8 ?? ?? ?? ?? bb ?? ?? ?? ?? [0-4] 6a 00 6a 00 6a 00 6a 00 6a 00 e8 ?? ?? ?? ?? 4b}  //weight: 1, accuracy: Low
        $x_1_2 = {8b c8 03 ca 73 05 e8 ?? ?? ?? ?? 8a 09 [0-4] 80 f1 ?? 03 d0 73 05 e8 ?? ?? ?? ?? 88 0a c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LokiBot_SR_2147733255_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LokiBot.SR!MTB"
        threat_id = "2147733255"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 40 68 00 30 00 00 68 ?? ?? 00 00 6a 00 e8 ?? ?? ?? ?? [0-5] [0-16] 33 c0 89 ?? ?? be ?? ?? ?? ?? bb ?? ?? ?? ?? [0-16] 8b [0-3] 03 ?? ?? [0-16] 8a ?? [0-16] (34|80) [0-2] [0-16] 88 ?? [0-16] [0-4] e8 ?? ?? ?? ?? [0-16] 43 4e 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LokiBot_SR_2147733255_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LokiBot.SR!MTB"
        threat_id = "2147733255"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 02 3c 61 72 [0-4] 3c 7a 77 [0-4] 2c 20 88 06 42 46 4b}  //weight: 1, accuracy: Low
        $x_1_2 = {b0 b7 8b 15 [0-4] 89 15 [0-4] 8b 15 [0-4] 8a 92 [0-4] 88 15 [0-4] 8b d6 03 d3 89 15 [0-4] 30 05 [0-4] [0-16] a0 [0-4] 8b 15 [0-4] 88 02 a1 [0-4] a3 [0-4] a1 [0-4] 83 c0 02 a3 [0-4] [0-16] 43 81 fb [0-4] 75 a1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LokiBot_DA_2147739868_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LokiBot.DA!MTB"
        threat_id = "2147739868"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 16 88 15 ?? ?? ?? ?? 30 05 ?? ?? ?? ?? [0-16] a0 ?? ?? ?? ?? e8 42 ?? ?? ?? ?? [0-16] ff 05 ?? ?? ?? ?? [0-16] 46 4b 75 b3 [0-16] 81 c7}  //weight: 1, accuracy: Low
        $x_1_2 = {bb 01 00 00 00 [0-16] 8b d0 03 d3 [0-16] c6 02 0b [0-16] 43 81 fb ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LokiBot_DC_2147739928_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LokiBot.DC!MTB"
        threat_id = "2147739928"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {8b 06 8a 80 ?? ?? ?? ?? a2 ?? ?? ?? ?? 8b c7 03 05 ?? ?? ?? ?? 89 06 [0-16] 8b 06 a3 ?? ?? ?? ?? [0-16] b0 33 [0-16] 32 05 ?? ?? ?? ?? [0-16] e8 ?? ?? ?? ?? [0-16] ff 05 ?? ?? ?? ?? [0-16] 43 81 fb ?? ?? ?? ?? 75}  //weight: 4, accuracy: Low
        $x_1_2 = {bb 01 00 00 00 [0-16] 8b ?? 03 ?? [0-16] c6 ?? ?? [0-16] 43 81 fb ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
        $x_4_3 = {33 c0 89 04 24 b8 ?? ?? ?? ?? [0-16] 8b f7 03 f2 [0-16] 8a 08 [0-16] 80 f1 ec [0-16] 88 0e [0-16] 42 [0-16] ff 04 24 40 81 3c 24 e5 5b 00 00 75}  //weight: 4, accuracy: Low
        $x_4_4 = {33 c0 a3 8c 0c 49 00 [0-16] 33 db [0-16] 8b 06 [0-16] 03 05 ?? ?? ?? ?? [0-16] b2 d2 [0-16] a3 ?? ?? ?? ?? [0-16] 8b c3 [0-16] 8a 80 ?? ?? ?? ?? a2 ?? ?? ?? ?? [0-16] 30 15 ?? ?? ?? ?? [0-16] 8a 15 ?? ?? ?? ?? [0-16] 8b c2 e8 ?? ?? ?? ?? [0-16] 8b 06 [0-16] 40 89 06 [0-16] 43 81 fb ?? ?? ?? ?? 75}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            ((2 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_LokiBot_DD_2147739930_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LokiBot.DD!MTB"
        threat_id = "2147739930"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c7 8b de 8b d3 e8 ?? ?? ff ff 90 [0-16] 46 81 fe ?? ?? 00 00 75}  //weight: 1, accuracy: Low
        $x_1_2 = {8b c8 03 ca 8b c2 b2 ?? 32 90 ?? ?? ?? 00 88 11 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LokiBot_DD_2147739930_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LokiBot.DD!MTB"
        threat_id = "2147739930"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 03 01 00 00 00 [0-16] 8b d0 03 13 [0-16] c6 02 ?? [0-16] ff 03 81 3b ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 03 8a 80 ?? ?? ?? ?? a2 ?? ?? ?? ?? [0-16] b0 6b [0-16] 30 05 ?? ?? ?? ?? [0-16] a0 ?? ?? ?? ?? e8 ?? ?? ?? ?? [0-16] 8b 07 40 89 07 [0-16] ff ?? 81 3b ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LokiBot_DE_2147739946_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LokiBot.DE!MTB"
        threat_id = "2147739946"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b0 c0 8b 15 ?? ?? ?? ?? 89 16 8b d3 [0-16] 03 15 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? [0-16] 8b 16 8a 92 ?? ?? ?? ?? 88 15 ?? ?? ?? ?? 30 05 ?? ?? ?? ?? [0-16] a0 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 89 16 e8 ?? ?? ?? ?? [0-16] a1 ?? ?? ?? ?? 89 06 [0-16] 8b 06 83 c0 02 a3 ?? ?? ?? ?? 43 81}  //weight: 1, accuracy: Low
        $x_1_2 = {bb db 7c b9 0d 90 4b 75 fc}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LokiBot_DG_2147740045_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LokiBot.DG!MTB"
        threat_id = "2147740045"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {be 01 00 00 00 [0-16] 8b d0 03 d6 [0-16] c6 02 59 [0-16] 46 81 fe a5 a6 f1 22 75 eb}  //weight: 1, accuracy: Low
        $x_1_2 = {33 c0 89 07 [0-64] b3 ?? [0-16] a3 ?? ?? ?? ?? [0-16] 8b c6 [0-16] 8a 80 ?? ?? ?? ?? a2 ?? ?? ?? ?? [0-16] 8b d3 a0 ?? ?? ?? ?? e8 ?? ?? ?? ?? a2 ?? ?? ?? ?? [0-16] 8a 1d ?? ?? ?? ?? [0-16] 8b c3 e8 ?? ?? ?? ?? [0-16] 8b 07 [0-16] 40 89 07 [0-16] 46 81 fe ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LokiBot_DG_2147740045_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LokiBot.DG!MTB"
        threat_id = "2147740045"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "fxyybb" ascii //weight: 1
        $x_1_2 = {5c 54 45 4d 50 5c 6e 73 [0-15] 2e 74 6d 70 5c [0-15] 2e 64 6c 6c}  //weight: 1, accuracy: Low
        $x_1_3 = "unknowndll.pdb" ascii //weight: 1
        $x_1_4 = {5c 4c 6f 61 64 65 72 5c [0-15] 5c 52 65 6c 65 61 73 65 5c [0-15] 2e 70 64 62}  //weight: 1, accuracy: Low
        $x_1_5 = "unhandled algorithm" ascii //weight: 1
        $x_1_6 = "V2CAPIDSAPRIVATEBLOB" ascii //weight: 1
        $x_1_7 = "Toolhelp32ReadProcessMemory" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LokiBot_DH_2147740070_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LokiBot.DH!MTB"
        threat_id = "2147740070"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {be 1a 58 c6 08 [0-16] 4e 75}  //weight: 1, accuracy: Low
        $x_1_2 = {8b c6 03 c7 a3 ?? ?? ?? ?? a1 3c 9c 48 00 8a 98 ?? ?? ?? ?? 8a 15 ?? ?? ?? ?? 8b c3 e8 ?? ?? ?? ?? a2 ?? ?? ?? ?? [0-16] 8a 1d ?? ?? ?? ?? [0-16] a1 ?? ?? ?? ?? a3 ?? ?? ?? ?? 8b c3 e8 ?? ?? ?? ?? [0-16] a1 ?? ?? ?? ?? a3 ?? ?? ?? ?? [0-16] a1 ?? ?? ?? ?? 83 c0 02 a3 ?? ?? ?? ?? 46 81 fe ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LokiBot_DH_2147740070_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LokiBot.DH!MTB"
        threat_id = "2147740070"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$eea4ec6d-47af-4e15-9feb-5891c6bab72c" ascii //weight: 1
        $x_1_2 = "frmBaseSF" ascii //weight: 1
        $x_1_3 = "FromBase64String" ascii //weight: 1
        $x_1_4 = "DebuggableAttribute" ascii //weight: 1
        $x_1_5 = "CreateInstance" ascii //weight: 1
        $x_1_6 = "Activator" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LokiBot_DI_2147740083_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LokiBot.DI!MTB"
        threat_id = "2147740083"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {57 6a 40 68 [0-64] 8b 07 8a 98 ?? ?? ?? ?? [0-16] 8a 15 ?? ?? ?? ?? 8b c3 e8 ?? ?? ?? ?? a2 ?? ?? ?? ?? [0-16] 8a 1d ?? ?? ?? ?? a1 ?? ?? ?? ?? 89 07 [0-16] 8b c3 e8 ?? ?? ?? ?? [0-16] a1 ?? ?? ?? ?? 89 07 8b 07 83 c0 02 a3 ?? ?? ?? ?? [0-16] 46 81 fe ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
        $x_1_2 = {be e8 dd 11 0c [0-16] 4e 75 f9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LokiBot_DJ_2147740114_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LokiBot.DJ!MTB"
        threat_id = "2147740114"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {bb 01 00 00 00 8b ca 03 cb [0-4] c6 01 d9 43 48 75 f3}  //weight: 1, accuracy: Low
        $x_1_2 = {b2 bc 8b c3 85 c0 79 05 e8 ?? ?? ?? ?? 8b fe 03 f8 [0-16] a1 ?? ?? ?? ?? 3d ?? ?? ?? ?? 76 05 e8 ?? ?? ?? ?? 8a 80 ?? ?? ?? ?? 32 c2 88 07 [0-16] 83 05 ?? ?? ?? ?? 02 43 81 fb ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LokiBot_DL_2147740448_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LokiBot.DL!MTB"
        threat_id = "2147740448"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 f0 0f be 80 ?? ?? ?? ?? 83 f0 ?? 8b 8d 5c ff ff ff 03 4d f0 88 01 a1 ?? ?? ?? ?? 3b 05 ?? ?? ?? ?? 7f 07 c6 05 f5 45 00 10 ?? 0f bf 05 ?? ?? ?? ?? 85 c0 74 12 0f bf 05 ?? ?? ?? ?? 85 c0 74 07 c6 05 ?? ?? ?? ?? ?? 8b 45 f0 40 89 45 f0 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LokiBot_DL_2147740448_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LokiBot.DL!MTB"
        threat_id = "2147740448"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c2 03 c3 [0-5] c6 [0-4] [0-5] 43 81 fb [0-4] 75 ec}  //weight: 1, accuracy: Low
        $x_1_2 = {33 c0 89 45 [0-4] 33 c9 [0-5] 8b c1 [0-16] 8a 90 [0-4] [0-16] 80 f2 e3 [0-16] 8b c6 03 c1 [0-16] 89 45 fc [0-16] 88 55 fb [0-16] 8b 55 fc [0-16] 8a 45 fb [0-16] 88 02 [0-5] 41 81 f9 ?? ?? ?? ?? 75 bf}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LokiBot_DO_2147740899_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LokiBot.DO!MTB"
        threat_id = "2147740899"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {bb 01 00 00 00 [0-5] 8b c6 03 c3 [0-5] c6 00 [0-16] 43 81 fb [0-4] 75}  //weight: 1, accuracy: Low
        $x_1_2 = {33 c0 89 45 [0-21] 8a 90 ?? ?? ?? ?? [0-5] 80 f2 ?? [0-21] 88 55 fb [0-21] 41 81 f9 ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LokiBot_DP_2147740972_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LokiBot.DP!MTB"
        threat_id = "2147740972"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 6a 40 68 ?? ?? ?? ?? 8b 45 fc 50 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {33 db 8b f3 8a [0-6] 80 f2 1b 03 75 fc 88 16 [0-5] 40 40 [0-5] 43 81 fb [0-2] 00 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LokiBot_DQ_2147740973_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LokiBot.DQ!MTB"
        threat_id = "2147740973"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {54 6a 40 68 ?? ?? ?? ?? 56 e8 ?? ?? ?? ?? 33}  //weight: 1, accuracy: Low
        $x_1_2 = {33 c0 8b f8 [0-5] 8a 8a ?? ?? ?? ?? 80 f1 5c 03 fe 88 0f [0-5] 42 [0-5] 42 40 3d ?? ?? 00 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LokiBot_DU_2147741202_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LokiBot.DU!MTB"
        threat_id = "2147741202"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {85 d2 0f 84 [0-32] bb 01 00 00 00 [0-32] 43 81 fb ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
        $x_1_2 = {8b eb 81 fd [0-16] 8a 85 [0-16] 80 f2 6c [0-16] e8 [0-32] ff 43 81 fb ?? ?? 00 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LokiBot_DW_2147741343_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LokiBot.DW!MTB"
        threat_id = "2147741343"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {85 d2 0f 84 [0-32] bb 01 00 00 00 [0-32] 43 81 fb ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
        $x_1_2 = {53 56 57 e8 [0-48] b0 ?? [0-16] 8b ?? [0-16] 81 fa ?? ?? 00 00 [0-16] 8a 92 ?? ?? ?? ?? [0-5] 32 d0 [0-16] e8 [0-21] 81 fb ?? ?? 00 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LokiBot_DX_2147741702_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LokiBot.DX!MTB"
        threat_id = "2147741702"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {f6 d9 c0 c1 02 2a c8 80 f1 d1 c0 c1 02 f6 d9 c0 c1 03 2a c8 f6 d1 80 e9 21 80 f1 6e 2a c8 88 88 [0-4] 40 3d ?? ?? ?? ?? 72}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LokiBot_DX_2147741702_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LokiBot.DX!MTB"
        threat_id = "2147741702"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 e0 5e 00 00 [0-8] 66 81 f9 3f de 83 e9 04 [0-8] 8b 1c 0f [0-37] 31 f3 [0-48] 09 1c 08 [0-16] 7f [0-8] 89 c6 [0-16] c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LokiBot_FA_2147741967_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LokiBot.FA!MTB"
        threat_id = "2147741967"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {bb 01 00 00 00 [0-5] 8b c6 03 c3 [0-5] c6 00 [0-16] 43 81 fb [0-4] 75}  //weight: 1, accuracy: Low
        $x_1_2 = {83 c4 10 5f 5e c3 90 [0-16] 8b c8 90 [0-16] 8b c2 90 [0-16] 8a 80 ?? ?? ?? ?? 90 [0-16] 34 ?? 90 [0-16] 88 01 90 [0-16] 90 [0-16] 90 [0-16] 90 [0-16] 90 [0-16] c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LokiBot_HA_2147749886_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LokiBot.HA!MTB"
        threat_id = "2147749886"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "D7YX1K0lDNnVdoNfCkY9Xsi99q2lzpBkYq6tMyht91" wide //weight: 1
        $x_1_2 = "huk5Y3YpuhkCiMgDW1izp4250" wide //weight: 1
        $x_1_3 = "G68o1Av5QLnypoLRn59A206" wide //weight: 1
        $x_1_4 = "hh5dj1zShzPBUyzxPRHjbUtvpcY9104" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LokiBot_GM_2147753470_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LokiBot.GM!MTB"
        threat_id = "2147753470"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 06 88 45 [0-64] 8a 84 85 ?? ?? ?? ?? 32 45 ?? 8b 55 ?? 88 02 [0-48] ff 4d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LokiBot_AG_2147754289_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LokiBot.AG!MTB"
        threat_id = "2147754289"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 04 38 88 45 [0-64] 8b 45 [0-100] 8b 84 85 [0-4] 33 d2 8a 55 ?? 33 c2 [0-64] 8b 55 [0-1] 88 02 [0-32] ff 4d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LokiBot_GA_2147756410_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LokiBot.GA!MTB"
        threat_id = "2147756410"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 f8 8a 80 [0-32] 34 e9 8b 55 ?? 03 55 ?? 88 02 [0-32] 8b 45 ?? 8a 80 [0-32] 8b 55 ?? 03 55 ?? 88 02}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LokiBot_GA_2147756410_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LokiBot.GA!MTB"
        threat_id = "2147756410"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "qdqfQw0c8wHeTVHQprdvac5FzvK92LjF40" wide //weight: 1
        $x_1_2 = "DFL6IGgaT97bwA1ZJaQ5Z5gxO203" wide //weight: 1
        $x_1_3 = "Indskrivningsarbejdes" wide //weight: 1
        $x_1_4 = "Foresprgselstidspunktet8" wide //weight: 1
        $x_1_5 = "Kunstnerproblematiks9" wide //weight: 1
        $x_1_6 = "jZ5gwOtLjQkD60" wide //weight: 1
        $x_1_7 = "iAC0Mk3VClHcmvdVEvNyVB12" wide //weight: 1
        $x_1_8 = "MSVBVM60.DLL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LokiBot_KM_2147772948_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LokiBot.KM!MTB"
        threat_id = "2147772948"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d1 e0 0b d0 88 95 ?? ?? ?? ?? 0f b6 8d ?? ?? ?? ?? 33 8d ?? ?? ?? ?? 88 8d ?? ?? ?? ?? 0f b6 95 ?? ?? ?? ?? 81 c2 8c 00 00 00 88 95 ?? ?? ?? ?? 0f b6 85 ?? ?? ?? ?? f7 d8 88 85 ?? ?? ?? ?? 8b 8d ?? ?? ?? ?? 8a 95 ?? ?? ?? ?? 88 94 0d ?? ?? ?? ?? e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LokiBot_DFA_2147787630_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LokiBot.DFA!MTB"
        threat_id = "2147787630"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 44 24 28 00 00 00 00 f7 f1 0f b6 0d ?? ?? ?? ?? 0f af c1 8b 0d ?? ?? ?? ?? 0f af 0d cc 24 4a 00 03 c1 0f b7 0d ?? ?? ?? ?? 2b c1 2b 05 a4 2a 4a 00 40 a3 14 27 4a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LokiBot_ZZ_2147787631_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LokiBot.ZZ!MTB"
        threat_id = "2147787631"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0a 74 a4 ac 58 b1 19 2f d4 c8 30 66 50 30 77 d5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LokiBot_RAN_2147793895_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LokiBot.RAN!MTB"
        threat_id = "2147793895"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 d0 d6 1c 00 3b f0 7f 1f ff 15 ?? ?? ?? ?? 6a 00 6a 00 e8 ?? ?? ?? ?? ff d3 8b c7 03 c6 0f 80 f4 00 00 00 8b f0 eb d8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LokiBot_RAO_2147793896_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LokiBot.RAO!MTB"
        threat_id = "2147793896"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {09 3c 28 0f [0-16] 83 ed 58 [0-16] 83 c5 54 7d [0-16] eb [0-48] 50 [0-16] c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LokiBot_IUY_2147797876_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LokiBot.IUY!MTB"
        threat_id = "2147797876"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 45 fc 8b 5d 08 eb 05 80 37 47 eb 07 8b 7d fc 01 df eb f4 90 40 3d 08 5e 00 00 75 e3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LokiBot_IUX_2147797877_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LokiBot.IUX!MTB"
        threat_id = "2147797877"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 4d fc 8b 45 fc 8b 55 08 01 d0 80 30 b8 41 81 f9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LokiBot_UY_2147806247_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LokiBot.UY!MTB"
        threat_id = "2147806247"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c7 45 44 75 1c 26 34 c7 45 98 f3 3c 60 32 c7 85 40 fe ff ff 37 2f cb 38 c7 45 a0 89 59 48 52 c7 85 a0 fe ff ff ca e0 34 6f c7 85 e8 fe ff ff 20 13 17 00 c7 85 48 fe ff ff 3b 9d af 24}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LokiBot_RPH_2147813355_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LokiBot.RPH!MTB"
        threat_id = "2147813355"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 10 89 38 0f b6 d2 89 16 8b 00 03 c2 23 c1 8a 04 85}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LokiBot_RPI_2147813356_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LokiBot.RPI!MTB"
        threat_id = "2147813356"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {90 8b 45 f4 8a 80 04 5e 45 00 8b 55 f0 88 02 90 90}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LokiBot_RPJ_2147813357_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LokiBot.RPJ!MTB"
        threat_id = "2147813357"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {88 02 83 45 fc 01 73 05 e8 a6 b5 fa ff 90 90 90 ff 45 f8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LokiBot_RPN_2147813631_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LokiBot.RPN!MTB"
        threat_id = "2147813631"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0b c1 88 45 ff 0f b6 55 ff 2b 55 f8 88 55 ff 8b 45 f8 8a 4d ff 88 88}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LokiBot_RPO_2147813632_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LokiBot.RPO!MTB"
        threat_id = "2147813632"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {88 45 ff 0f b6 4d ff 83 e9 79 88 4d ff 8b 55 f8 8a 45 ff 88 82}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LokiBot_RPO_2147813632_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LokiBot.RPO!MTB"
        threat_id = "2147813632"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 f8 03 45 fc 88 10 8b 4d f8 03 4d fc 8a 11 80 ea 01 8b 45 f8 03 45 fc 88 10 e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LokiBot_RPP_2147813633_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LokiBot.RPP!MTB"
        threat_id = "2147813633"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {88 4d ff 0f b6 55 ff 81 f2 8d 00 00 00 88 55 ff 8b 45 f8 8a 4d ff 88 88}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LokiBot_RPP_2147813633_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LokiBot.RPP!MTB"
        threat_id = "2147813633"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 c8 f7 e3 d1 ea 83 e2 fc 8d 04 52 f7 d8 8b 14 24 8a 04 07 30 04 0a 41 47 39 ce 75 e3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LokiBot_RPQ_2147813634_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LokiBot.RPQ!MTB"
        threat_id = "2147813634"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {88 4d ff 0f b6 55 ff 81 f2 b9 00 00 00 88 55 ff 8b 45 f8 8a 4d ff 88 88}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LokiBot_RPR_2147813635_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LokiBot.RPR!MTB"
        threat_id = "2147813635"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2a c8 32 c8 b2 61 2a d1 80 f2 b3 2a d0 32 d0 b1 01 2a ca}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LokiBot_RPR_2147813635_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LokiBot.RPR!MTB"
        threat_id = "2147813635"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 4d ec 8b 45 ec 29 45 fc 89 7d f4 8b 45 e0 01 45 f4 2b 75 f4 ff 4d e8 8b 4d fc 89 75 ec}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LokiBot_RPS_2147813636_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LokiBot.RPS!MTB"
        threat_id = "2147813636"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c6 83 e0 03 83 c6 05 8a 44 05 fc 30 82 ?? ?? ?? ?? 83 c2 05 81 fa 05 5a 00 00 72 a9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LokiBot_RPT_2147813637_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LokiBot.RPT!MTB"
        threat_id = "2147813637"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {02 c8 80 f1 7b b2 5c 2a d1 32 d0 b1 12 2a ca c0 c9 02 2a c8 88 88}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LokiBot_RPT_2147813637_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LokiBot.RPT!MTB"
        threat_id = "2147813637"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {88 45 ff 0f b6 4d ff 2b 4d f8 88 4d ff 0f b6 55 ff 81 f2 ?? ?? ?? ?? 88 55 ff 0f b6 45 ff f7 d8 88 45 ff 0f b6 4d ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LokiBot_RPT_2147813637_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LokiBot.RPT!MTB"
        threat_id = "2147813637"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 04 0e 2c [0-16] 02 c1 [0-16] f6 d8 [0-16] f6 d0 [0-16] 32 c1 [0-16] 02 c1 [0-16] f6 d8 [0-16] 32 c1 f6 d8 88 04 0e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LokiBot_RPL_2147816183_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LokiBot.RPL!MTB"
        threat_id = "2147816183"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 c0 fe 0c 07 8b 0c 24 fe 0c 01 8b 0c 24 fe 04 01 8b 0c 24 80 04 01 ?? 8b 0c 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LokiBot_RPM_2147816184_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LokiBot.RPM!MTB"
        threat_id = "2147816184"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {fe 0c 07 8b 0c 24 80 34 01 ?? 8b 0c 24 80 04 01 ?? 8b 0c 24 80 04 01 ?? 8b 0c 24 80 34 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LokiBot_RPW_2147816648_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LokiBot.RPW!MTB"
        threat_id = "2147816648"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "resocialiseringernes1" ascii //weight: 1
        $x_1_2 = "Forbigaaelse1" ascii //weight: 1
        $x_1_3 = "FIKSERENDES1" ascii //weight: 1
        $x_1_4 = "Stiftmosaikgulvets1" ascii //weight: 1
        $x_1_5 = "Skovvsenet@REVOYAGE.sti0" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LokiBot_RPX_2147816649_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LokiBot.RPX!MTB"
        threat_id = "2147816649"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 55 fc 83 c2 01 89 55 fc 81 7d fc da 16 00 00 7d 27 8b 45 fc 99 b9 0c 00 00 00 f7 f9 8b 45 e4 0f b6 0c 10 8b 55 f8 03 55 fc 0f b6 02 33 c1 8b 4d f8 03 4d fc 88 01 eb c7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LokiBot_RPX_2147816649_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LokiBot.RPX!MTB"
        threat_id = "2147816649"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 65 c4 00 83 7d c4 01 73 06 83 65 a8 00 eb 08 e8 ?? ?? ?? ?? 89 45 a8 ba ?? ?? ?? ?? 8b 45 c4 8b 4d e4 8d 0c 81 e8 ?? ?? ?? ?? ff 75 c0 ff 75 bc ff 75 b8 ff 75 b4 8d 45 cc 50 e8 ?? ?? ?? ?? 89 45 ac 83 7d ac 00 75 b7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LokiBot_EU_2147817810_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LokiBot.EU!MTB"
        threat_id = "2147817810"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 01 66 8b 00 f6 c4 f9 74 ?? 8b 1d ?? ?? ?? ?? 8b 1b 03 1d ?? ?? ?? ?? 66 25 ff 0f 0f b7 c0 03 d8 a1 ?? ?? ?? ?? 01 03 83 01 02 4a 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LokiBot_ETT_2147819847_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LokiBot.ETT!MTB"
        threat_id = "2147819847"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {59 59 89 45 e8 6a 04 68 00 30 00 00 68 ?? ?? ?? ?? 6a 00 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 40 68 00 30 00 00 ff 75 f4 6a 00 ff 15}  //weight: 1, accuracy: High
        $x_1_3 = {6a 00 51 56 ff 75 e4 ff 34 18 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LokiBot_RPZ_2147832366_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LokiBot.RPZ!MTB"
        threat_id = "2147832366"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 f8 89 45 f0 [0-5] 8b 45 08 03 45 f0 8a 00 88 45 f7 [0-5] 8a 45 f7 34 20 8b 55 08 03 55 f0 88 02 [0-5] ff 45 f8 81 7d f8 [0-5] 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LokiBot_RPF_2147832448_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LokiBot.RPF!MTB"
        threat_id = "2147832448"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {88 45 ff 0f b6 45 ff 33 45 f8 88 45 ff 0f b6 45 ff 2b 45 f8 88 45 ff 8b 45 f4 03 45 f8 8a 4d ff 88 08 e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LokiBot_RPU_2147834324_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LokiBot.RPU!MTB"
        threat_id = "2147834324"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {88 55 ff 0f b6 4d ff 03 4d f8 88 4d ff 0f b6 55 ff 81 f2 ?? ?? ?? ?? 88 55 ff 0f b6 45 ff c1 f8 07 0f b6 4d ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LokiBot_SRPS_2147836056_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LokiBot.SRPS!MTB"
        threat_id = "2147836056"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8b 4d f8 03 4d fc 0f be 11 81 f2 d7 00 00 00 8b 45 f8 03 45 fc 88 10 8b 4d f8 03 4d fc 8a 11 80 c2 01 8b 45 f8 03 45 fc 88 10 8b 4d f8 03 4d fc 8a 11 80 ea 01 8b 45 f8 03 45 fc 88 10 8b 4d f8 03 4d fc}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LokiBot_SPQC_2147837801_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LokiBot.SPQC!MTB"
        threat_id = "2147837801"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {8a 04 37 fe c0 34 5b 04 78 34 99 04 65 88 04 37 46 3b f3 72 eb}  //weight: 7, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LokiBot_CN_2147841036_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LokiBot.CN!MTB"
        threat_id = "2147841036"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {89 c8 f7 e7 d1 ea 83 e2 fc 8d 04 52 89 ca 29 c2 0f b6 ?? ?? ?? ?? ?? 30 14 0e f7 d8 0f b6 ?? ?? ?? ?? ?? ?? 30 44 0e 01 83 c1 ?? 39 cb 75}  //weight: 5, accuracy: Low
        $x_1_2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Installer\\RunOnceEntries" ascii //weight: 1
        $x_1_3 = "\\msiexec /V" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LokiBot_CM_2147841038_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LokiBot.CM!MTB"
        threat_id = "2147841038"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b c1 6a 0c 99 5e f7 fe 8a 82 ?? ?? ?? ?? 30 04 0f 41 3b cb 72}  //weight: 5, accuracy: Low
        $x_1_2 = "GetTickCount" ascii //weight: 1
        $x_1_3 = "DllRegisterServer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LokiBot_CMZ_2147841263_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LokiBot.CMZ!MTB"
        threat_id = "2147841263"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {b8 ab aa aa aa f7 e6 8b c6 c1 ea ?? 8d 0c 52 c1 e1 ?? 2b c1 8a 80 ?? ?? ?? ?? 30 04 33 46 3b f7 72}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LokiBot_CMS_2147841264_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LokiBot.CMS!MTB"
        threat_id = "2147841264"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b c1 99 6a 0c 5e f7 fe 8a 82 ?? ?? ?? ?? 30 04 0b 41 3b cf 72}  //weight: 5, accuracy: Low
        $x_1_2 = "GetTickCount" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LokiBot_CMF_2147841803_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LokiBot.CMF!MTB"
        threat_id = "2147841803"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b c1 6a 0c 99 5e f7 fe 8a 82 ?? ?? ?? ?? 30 04 0f 41 3b cb 72}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LokiBot_CPL_2147846984_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LokiBot.CPL!MTB"
        threat_id = "2147846984"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {ff 36 66 0f 73 d4 ?? 66 85 d9 0f 6f d6 66 81 ff ?? ?? f7 c1 ?? ?? ?? ?? 38 f4 58 0f 73 f1 ee 66 f7 c3 ?? ?? 39 da 38 d0 39 c2 0f 67 c2 83 c6 ?? 38 ec 84 c3 85 d1 84 f4 66 85 c8 0f f8 ee 83 f8 00 74}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LokiBot_CBYB_2147853215_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LokiBot.CBYB!MTB"
        threat_id = "2147853215"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {99 03 04 24 13 54 24 04 83 c4 ?? 8b d1 8a 12 80 f2 ?? 88 10 ff 06 41 81 3e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LokiBot_MBHX_2147888653_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LokiBot.MBHX!MTB"
        threat_id = "2147888653"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {e4 70 ce 32 20 d0 35 ?? ?? ?? ?? d3 e0 b4 79 ef 9e 09 f6 6c}  //weight: 1, accuracy: Low
        $x_1_2 = {18 3f 40 00 33 f0 30 00 00 ff ff ff 08 00 00 00 01 00 00 00 05 00 00 00 e9 00 00 00 a4 3b 40 00 00 34 40 00 18 33 40 00 78 00 00 00 84}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LokiBot_RDJ_2147892069_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LokiBot.RDJ!MTB"
        threat_id = "2147892069"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0f b6 55 fe c1 fa 05 0f b6 45 fe c1 e0 03 0b d0}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LokiBot_NH_2147910554_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LokiBot.NH!MTB"
        threat_id = "2147910554"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "FILEINSTALL ( \"encrypted.bin\" , @TEMPDIR" ascii //weight: 2
        $x_2_2 = "RUNPE ( FILEREAD ( @TEMPDIR &" ascii //weight: 2
        $x_2_3 = "STRINGINSTR ( @SCRIPTDIR , \"AppData\" )" ascii //weight: 2
        $x_2_4 = "RUN ( @APPDATADIR & \"\\\" & @SCRIPTNAME )" ascii //weight: 2
        $x_2_5 = "REGWRITE ( STRINGREPLACE ( \"HKEY_CURRENTxentVersion\\Run" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LokiBot_SCMB_2147917937_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LokiBot.SCMB!MTB"
        threat_id = "2147917937"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {c1 e8 05 89 45 f8 8b 45 f8 03 45 e4 c7 05 ?? ?? ?? ?? ee 3d ea f4 33 c2 33 c1 2b f8 83 3d ?? ?? ?? ?? 0c 89 45 f8 75}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

