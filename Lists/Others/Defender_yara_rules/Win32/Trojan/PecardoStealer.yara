rule Trojan_Win32_PecardoStealer_RPY_2147798252_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PecardoStealer.RPY!MTB"
        threat_id = "2147798252"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PecardoStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 45 f8 ff 25 ?? ?? ?? ?? cc ff 30 e8 ?? ?? ?? ?? 59 a1 ?? ?? ?? ?? cc e8 ?? ?? ?? ?? 50 55 c3 cc aa 68 ?? ?? ?? ?? c3 e9 ?? ?? ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PecardoStealer_RPZ_2147805653_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PecardoStealer.RPZ!MTB"
        threat_id = "2147805653"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PecardoStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ac 32 c2 2a c2 32 c2 c0 c0 03 fe c8 32 c2 02 d6 aa e2 ed}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PecardoStealer_RPL_2147812459_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PecardoStealer.RPL!MTB"
        threat_id = "2147812459"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PecardoStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ac 2a c1 c0 c0 03 2a c1 32 c1 2c 5e 2a c1 2c 5e 34 32 2a c1 04 5e 04 5e 32 c1 34 32}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PecardoStealer_RPM_2147812460_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PecardoStealer.RPM!MTB"
        threat_id = "2147812460"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PecardoStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c0 c8 07 c0 c8 07 2a c1 c0 c8 07 04 43 2c 43 c0 c0 07 34 47 c0 c8 07 aa 4a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

