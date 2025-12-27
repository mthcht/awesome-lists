rule Trojan_Win32_Salatstealer_NL_2147956215_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Salatstealer.NL!MTB"
        threat_id = "2147956215"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Salatstealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {be 4d 30 6d ?? ec 48 d1 62 ?? 18 c4 16 54}  //weight: 2, accuracy: Low
        $x_1_2 = {09 ce 4b 08 ce 32 37 59}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Salatstealer_NR_2147956216_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Salatstealer.NR!MTB"
        threat_id = "2147956216"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Salatstealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {4e ed 26 8b eb 82 f6 ?? 17 ec 1f 30 71 ?? 4a eb b4 43}  //weight: 2, accuracy: Low
        $x_1_2 = {f6 30 95 13 c3 43 46 49}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Salatstealer_NT_2147956236_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Salatstealer.NT!MTB"
        threat_id = "2147956236"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Salatstealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {c5 36 23 14 f6 29 55 ?? 12 df 6b 09 ?? 6e 5b a6 3e}  //weight: 2, accuracy: Low
        $x_2_2 = {49 66 94 bc ?? ?? ?? ?? 33 0b 3a 1f}  //weight: 2, accuracy: Low
        $x_1_3 = "VirtualProtect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

