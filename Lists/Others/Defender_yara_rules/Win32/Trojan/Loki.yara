rule Trojan_Win32_Loki_SA_2147735573_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Loki.SA!MTB"
        threat_id = "2147735573"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Loki"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c6 03 e8 8d 56 04 8b c3 e8 ?? ?? ?? ?? 89 43 01 8b 07 89 43 05 89 1f 83 c3 0d 8b c3 2b c6 3d fc 0f 00 00 7c db}  //weight: 1, accuracy: Low
        $x_1_2 = {b0 39 8b d3 8b fe 03 fa 8b 15 ?? ?? ?? ?? 8a 92 ?? ?? ?? ?? [0-4] 32 d0 88 17 83 05 ?? ?? ?? ?? 02 [0-4] 43 81 fb 38 5e 00 00 75 d2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Loki_XR_2147752621_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Loki.XR!MTB"
        threat_id = "2147752621"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Loki"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {32 c2 88 01 c3 8d 40 00 55 8b ec 51 53 56 57 6a ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6a ?? e8 ?? ?? ?? ?? 8b f8 8b f7 33 c0 89 45 ?? bb ?? ?? ?? ?? 8b ce b2 ?? 8a 03 e8 ?? ?? ?? ?? 83 c6 ?? 73}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Loki_AB_2147951444_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Loki.AB!MTB"
        threat_id = "2147951444"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Loki"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff cc 31 00 00 d1 1c ?? 99 f5 55 59 43 be}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

