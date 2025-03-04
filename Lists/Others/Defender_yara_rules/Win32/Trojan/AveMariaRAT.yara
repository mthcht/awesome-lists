rule Trojan_Win32_AveMariaRAT_A_2147845376_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AveMariaRAT.A!MTB"
        threat_id = "2147845376"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AveMariaRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {f7 8a 44 15 98 30 04 19 41 81 f9}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AveMariaRAT_B_2147848910_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AveMariaRAT.B!MTB"
        threat_id = "2147848910"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AveMariaRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 01 f7 d0 85 c0 74 ?? 88 04 1a 83 e9 ?? 42 81 f9}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AveMariaRAT_C_2147849075_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AveMariaRAT.C!MTB"
        threat_id = "2147849075"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AveMariaRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a 04 0e c0 c8 ?? 32 82 ?? ?? ?? ?? c7 45 ?? ?? ?? ?? ?? 88 04 0e 8d 42 ?? 99 f7 7d ?? 41 81 f9}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AveMariaRAT_D_2147849247_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AveMariaRAT.D!MTB"
        threat_id = "2147849247"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AveMariaRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a 04 0e c0 c8 ?? 32 82 ?? ?? ?? ?? 88 04 0e 8d 42 ?? 99 c7 45 fc ?? ?? ?? ?? f7 7d ?? 41 81 f9}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AveMariaRAT_E_2147851354_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AveMariaRAT.E!MTB"
        threat_id = "2147851354"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AveMariaRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a 04 0f c0 c8 ?? 32 82 ?? ?? ?? ?? 41 88 44 0f ff 8d 42 ?? 99 f7 fe 3b cb 72}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AveMariaRAT_F_2147851359_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AveMariaRAT.F!MTB"
        threat_id = "2147851359"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AveMariaRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a 04 0b c0 c8 ?? 32 87 ?? ?? ?? ?? 41 88 44 ?? ff 8d 47 ?? 99 bf ?? ?? ?? ?? f7 ff 8b fa 3b ce 72}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AveMariaRAT_G_2147891361_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AveMariaRAT.G!MTB"
        threat_id = "2147891361"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AveMariaRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b c1 99 f7 ff 8a 44 14 ?? 30 04 29 41 81 f9}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AveMariaRAT_H_2147891818_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AveMariaRAT.H!MTB"
        threat_id = "2147891818"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AveMariaRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a 0e 30 0a 42 83 e8}  //weight: 2, accuracy: High
        $x_2_2 = {33 c2 c1 c0}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AveMariaRAT_PABD_2147892092_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AveMariaRAT.PABD!MTB"
        threat_id = "2147892092"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AveMariaRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 08 99 f7 7d e4 89 55 d8 81 7d 08 00 00 00 01 74 1b 8b 45 f8 03 45 08 0f be 08 8b 55 d8 0f be 44 15 10 33 c8 8b 55 f8 03 55 08 88 0a eb bf}  //weight: 1, accuracy: High
        $x_1_2 = {8a 04 02 88 44 0d 04 b9 01 00 00 00 6b d1 03 b8 01 00 00 00 6b c8 03 8b 45 0c 8a 14 10 88 54 0d 04 b8 01 00 00 00 6b c8 00 8b 55 0c c6 04 0a c2 b8 01 00 00 00 c1 e0 00 8b 4d 0c c6 04 01 10 ba 01 00 00 00 d1 e2 8b 45 0c c6 04 10 00 b9 01 00 00 00 6b d1 03 8b 45 0c c6 04 10 90}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

