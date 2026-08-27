rule Trojan_Win32_Curlygate_YDQ_2147974387_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Curlygate.YDQ!MTB"
        threat_id = "2147974387"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Curlygate"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {65 48 8b 04 25 30 00 00 00 48 8b 70 08 48 8b 1d fc 0f 01 00 31 c0 f0 48 0f b1 33 40 0f 94 c5 48 39 c6 0f 94 c0 40 08 e8}  //weight: 1, accuracy: High
        $x_1_2 = {48 8b 04 24 48 8b 00 8b 00 25 ff ff f8 00 3d 48 f7 c0 00 75 38 eb 10 48 8b 04 24 48 8b 08 48 83 c1 07 48 89 08 eb 12 48 8b 04 24}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Curlygate_YPR_2147974866_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Curlygate.YPR!MTB"
        threat_id = "2147974866"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Curlygate"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 04 01 0f b6 4c 24 61 31 c8 48 63 8c 24 a4 00 00 00 88 84 0c 70 02 00 00 8b 84 24 a4 00 00 00 83 c0 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Curlygate_YPS_2147975163_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Curlygate.YPS!MTB"
        threat_id = "2147975163"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Curlygate"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 0f b6 14 01 4c 63 05 ?? ?? ?? ?? 4c 8b 4d ?? 47 0f b6 14 01 44 31 d2 41 88 d3 8b 55 ?? 41 89 d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Curlygate_YPT_2147975164_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Curlygate.YPT!MTB"
        threat_id = "2147975164"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Curlygate"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f 28 4c 11 d0 0f 57 c8 0f 28 54 11 e0 0f 57 d0 0f 11 4c 08 d0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Curlygate_YBD_2147976166_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Curlygate.YBD!MTB"
        threat_id = "2147976166"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Curlygate"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b 0c 24 89 41 ?? 8b 44 24 ?? 35 ?? ?? ?? ?? 48 8b 0c ?? 89 41 ?? 48 89 c9 48 89 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Curlygate_YBE_2147976388_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Curlygate.YBE!MTB"
        threat_id = "2147976388"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Curlygate"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "164"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "postback_url" ascii //weight: 1
        $x_1_2 = "postback_path" ascii //weight: 1
        $x_1_3 = "crypto_domain" ascii //weight: 1
        $x_1_4 = "postback_id" ascii //weight: 1
        $x_10_5 = "SandboxieRpcSs.exe" ascii //weight: 10
        $x_10_6 = "httpdebugger.exe" ascii //weight: 10
        $x_10_7 = "x32dbg.exe" ascii //weight: 10
        $x_10_8 = "joeboxserver" ascii //weight: 10
        $x_10_9 = "xenservice" ascii //weight: 10
        $x_10_10 = "fuck_you" ascii //weight: 10
        $x_10_11 = "fuckyou" ascii //weight: 10
        $x_100_12 = "fuck" ascii //weight: 100
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 6 of ($x_10_*) and 4 of ($x_1_*))) or
            ((1 of ($x_100_*) and 7 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Curlygate_YBH_2147976904_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Curlygate.YBH!MTB"
        threat_id = "2147976904"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Curlygate"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_6_1 = {42 8d 04 02 44 0f b6 c0 42 0f b6 04 04 88 04 0c 42 88 14 04 0f b6 04 0c 03 c2 0f b6 c0 0f b6 0c 04 30 4f ff 48 83 ee 01 75}  //weight: 6, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Curlygate_YBUA_2147977034_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Curlygate.YBUA!MTB"
        threat_id = "2147977034"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Curlygate"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "WAoNu1Rts44ObP7Ds7NMU" wide //weight: 2
        $x_2_2 = "US7VT6hACnX2kFhtu2572d9" wide //weight: 2
        $x_2_3 = "T94R3I2YHBrpg26mAt" wide //weight: 2
        $x_2_4 = "iFKC3jUj2FKf3Yb1oosbhquV3QY" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

