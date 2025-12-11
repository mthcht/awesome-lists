rule Trojan_Win32_CoinStealer_BC_2147809809_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinStealer.BC!MTB"
        threat_id = "2147809809"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c8 83 f1 3c 81 e9 ?? ?? ?? ?? 03 cf 81 e9 ?? ?? ?? ?? 89 4d}  //weight: 1, accuracy: Low
        $x_1_2 = {2b c7 83 c0 4c 81 f0 ?? ?? ?? ?? 2b c6 33 05 ?? ?? ?? ?? 81 e8 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 89 45}  //weight: 1, accuracy: Low
        $x_1_3 = "VirtualProtect" ascii //weight: 1
        $x_1_4 = "VirtualAlloc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CoinStealer_BD_2147810202_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinStealer.BD!MTB"
        threat_id = "2147810202"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {cc f7 d0 cc 8b 54 24 08 33 c8 e9}  //weight: 1, accuracy: High
        $x_1_2 = {33 c8 33 c8 33 c8 33 c8 33 c8 33 c8 64 89 0d}  //weight: 1, accuracy: High
        $x_1_3 = "Eliminamos los virus arrancando" ascii //weight: 1
        $x_1_4 = "eliminar cualquier virus" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CoinStealer_GNM_2147810545_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinStealer.GNM!MTB"
        threat_id = "2147810545"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 45 f4 8b 45 14 81 e8 ?? ?? ?? ?? 03 45 ?? 83 f0 ?? 2b 45 ?? 33 c0 81 e8 ?? ?? ?? ?? 33 05 ?? ?? ?? ?? 81 e8 ?? ?? ?? ?? 89 45 ?? 8b c7 5f 58 8b e5 5d c3}  //weight: 10, accuracy: Low
        $x_10_2 = {89 45 20 b9 2c 00 00 00 81 e9 ?? ?? ?? ?? 03 0d ?? ?? ?? ?? 81 e9 ?? ?? ?? ?? 33 0d ?? ?? ?? ?? 2b 4d 1c 89 4d cc 8b c5 59 8b e5 5d c3}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CoinStealer_CB_2147811825_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinStealer.CB!MTB"
        threat_id = "2147811825"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2a c1 2a c1 c0 c0 05 34 51 c0 c0 05 aa 4a 0f 85}  //weight: 1, accuracy: High
        $x_1_2 = {2a c1 32 c1 32 c1 34 51 2a c1 32 c1 c0 c8 05 32 c1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CoinStealer_CD_2147812746_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinStealer.CD!MTB"
        threat_id = "2147812746"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {32 c1 2a c1 c0 c8 ?? 2a c1 aa 4a 0f 85}  //weight: 2, accuracy: Low
        $x_1_2 = "VirtualAlloc" ascii //weight: 1
        $x_1_3 = "IsDebuggerPresent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CoinStealer_CA_2147816189_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinStealer.CA!MTB"
        threat_id = "2147816189"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {32 c1 32 c1 2a c1 34 ?? 34 ?? 2a c1 c0 c0 ?? 2a c1 aa 4a 0f 85}  //weight: 2, accuracy: Low
        $x_1_2 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_3 = "GetTickCount" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CoinStealer_GTF_2147836297_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinStealer.GTF!MTB"
        threat_id = "2147836297"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {32 c5 88 42 03 8a 42 f4 32 45 fd 88 42 04 8a 42 f5 32 c1 88 42 05 8a 42 f6 32 c4 43 88 42 06 83 c2 ?? 83 fb 2c 0f 82}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CoinStealer_PAGO_2147953250_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinStealer.PAGO!MTB"
        threat_id = "2147953250"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0f b6 0c 03 32 4d ff 8b 3e 88 0c 07 40 4a 75 f0}  //weight: 2, accuracy: High
        $x_1_2 = "XRP=" ascii //weight: 1
        $x_1_3 = "DOT=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CoinStealer_AMTB_2147959262_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinStealer!AMTB"
        threat_id = "2147959262"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinStealer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 74 74 70 90 02 01 3a 2f 2f 61 70 69 2e 74 65 6c 65 67 72 61 6d 2e 6f 72 67 2f 62 6f 74 38 33 33 33 34 36 39 30 36 34 3a 41 41 48 48 34 61 48 33 78 4c 6b 6f 4b 76 56 52 7a 43 78 77 68 41 38 2d 72 78 35 51 34 51 4d 64 4e 52 45 2f 73 65 6e 64 4d 65 73 73 61 67 65}  //weight: 1, accuracy: High
        $x_1_2 = "ledger live" ascii //weight: 1
        $x_1_3 = "buttoniLostMy" ascii //weight: 1
        $x_1_4 = "LedgerAppMutex" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

