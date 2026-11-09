rule Trojan_Win64_AcrStealer_FN_2147980810_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AcrStealer.FN!MTB"
        threat_id = "2147980810"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AcrStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 f0 24 88 05}  //weight: 1, accuracy: High
        $x_2_2 = {83 e8 01 0f b6 04 02 0f b6 12 01 d0}  //weight: 2, accuracy: High
        $x_1_3 = "ChromeUpdateMain" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_AcrStealer_HN_2147980869_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AcrStealer.HN!MTB"
        threat_id = "2147980869"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AcrStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 f0 24 88 05}  //weight: 1, accuracy: High
        $x_2_2 = {83 e8 01 0f b6 04 02 0f b6 12 01 d0}  //weight: 2, accuracy: High
        $x_1_3 = "ChromeUpdateMain" ascii //weight: 1
        $x_1_4 = {01 c8 31 c2 81 f2 ?? ?? 00 00 89 d1 81 e1 ?? ?? 00 00 01 c8 89 d1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_AcrStealer_IN_2147981077_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AcrStealer.IN!MTB"
        threat_id = "2147981077"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AcrStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 f2 31 c9 44 0f af f0}  //weight: 1, accuracy: High
        $x_2_2 = {89 d1 81 e1 ?? ?? 00 00 01 c1 89 d0 c1 ea 03}  //weight: 2, accuracy: Low
        $x_1_3 = "C:\\Program Files\\x" ascii //weight: 1
        $x_1_4 = {31 c9 ff 15 ?? ?? 01 00 31 c9 0f b6 f8 ff 15 ?? ?? 01 00 31 c9 0f bf f0 ff 15 ?? ?? 01 00 01 c6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_AcrStealer_KN_2147981352_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AcrStealer.KN!MTB"
        threat_id = "2147981352"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AcrStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {49 d3 e1 49 ff c9 48 89 c2 4c 21 ca 44 89 d1 83 e9 08}  //weight: 1, accuracy: High
        $x_1_2 = "C:\\Program Files\\x" ascii //weight: 1
        $x_2_3 = {41 b8 a5 a5 a5 a5 41 0f 44 c0 41 89 c0 41 c1 e0 0d 44 31 c0 41 89 c0 41 c1 e8 11 44 31 c0 41 89 c0 41 c1 e0 05 44 31 c0}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_AcrStealer_LN_2147981357_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AcrStealer.LN!MTB"
        threat_id = "2147981357"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AcrStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e0 03 83 c0 3c 89 44 24 0c 8b 44 24 08 8b 4c 24 0c 81 e1}  //weight: 1, accuracy: High
        $x_1_2 = "C:\\Program Files\\x" ascii //weight: 1
        $x_2_3 = {01 c8 89 44 24 08 8b 44 24 0c 0d ?? ?? 00 00 89 44 24 0c 8b 44 24 08 8b 4c 24 0c}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_AcrStealer_BA_2147981547_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AcrStealer.BA!MTB"
        threat_id = "2147981547"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AcrStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {48 01 d0 44 29 c1 89 ca 88 10 8b 45 f4 41 89 c0 8b 45 f0 89 c1 48 8b 55 10 48 8b 45 f8 48 01 d0 44 89 c2 31 ca 88 10}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_AcrStealer_QN_2147981593_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AcrStealer.QN!MTB"
        threat_id = "2147981593"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AcrStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 14 24 8b 44 24 ?? c1 e8 ?? d1 e0 89 44 24}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 4c 24 14 81 e1 ?? ?? 00 00 01 c8 89 44 24 ?? 8b 44 24 ?? 33 44 24}  //weight: 1, accuracy: Low
        $x_1_3 = "C:\\Program Files\\x" ascii //weight: 1
        $x_2_4 = {eb 40 8b 44 24 ?? 83 c0 1e 89 44 24 ?? eb 33 8b 44 24 ?? 83 c0 39 89}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_AcrStealer_KK_2147981638_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AcrStealer.KK!MTB"
        threat_id = "2147981638"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AcrStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {41 0f b6 04 12 83 f0 43 0f b6 c0 66 89 04 51 48 83 c2 01 49 39 d1}  //weight: 20, accuracy: High
        $x_10_2 = {31 c9 ff 15 ?? ?? 01 00 31 c9 0f b6 f8 ff 15 ?? ?? 01 00 31 c9 0f bf f0 ff 15 ?? ?? 01 00 01 c6}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_AcrStealer_TN_2147981768_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AcrStealer.TN!MTB"
        threat_id = "2147981768"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AcrStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {01 ca 89 d1 c1 e9 05 01 c1 89 c8}  //weight: 1, accuracy: High
        $x_1_2 = {01 d0 31 45 fc 48 83 45 f0 01 48 8b 45 f0 48 3b 45 18}  //weight: 1, accuracy: High
        $x_1_3 = "C:\\Program Files\\x" ascii //weight: 1
        $x_2_4 = "GetAsyncKeyState" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

