rule Trojan_Win32_DCRat_EB_2147840297_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DCRat.EB!MTB"
        threat_id = "2147840297"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {8a 84 3c 10 01 00 00 88 84 34 10 01 00 00 88 8c 3c 10 01 00 00 0f b6 84 34 10 01 00 00 03 c2 0f b6 c0 8a 84 04 10 01 00 00 30 83}  //weight: 7, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DCRat_A_2147843115_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DCRat.A!MTB"
        threat_id = "2147843115"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 85 c8 aa fe ff c1 e0 ?? 8d 8d f8 aa fe ff 0f b6 14 08 f7 da 8b 85 c8 aa fe ff c1 e0 ?? 8d 8d f8 aa fe ff 88 14 08 eb}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DCRat_MA_2147844081_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DCRat.MA!MTB"
        threat_id = "2147844081"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {e9 96 21 a3 69 0c 21 3d 24 0c 21 a3 e9 0b 21 fb 3b ce 01 af d8 a2 91 25 14 aa 4b f5 ca 69 fb ed 0a 08 bd 7d be 86 0e f6 c4 5f c2 ef 56 d6 2f bd}  //weight: 5, accuracy: High
        $x_5_2 = {7b 24 bc c0 ac e9 16 d0 c6 34 f5 33 50 f2 bb 1f 75 64 fa a1 94 75 62 b4 23 2f 52 1b 92 8d 84 d7 f9 f7 e9 4d 34 79 5b 13 7a 28 39 64 76 a4 d9 9a}  //weight: 5, accuracy: High
        $x_5_3 = {e0 00 22 01 0b 01 08 00 00 9a 13 00 00 92 1d 00 00 00 00 00 c0 03 55 00 00 20 00 00 00 c0 13 00 00 00 40 00 00 20 00 00 00 02}  //weight: 5, accuracy: High
        $x_1_4 = ".themida" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DCRat_RPX_2147845431_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DCRat.RPX!MTB"
        threat_id = "2147845431"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 8d ec aa fe ff 83 c1 01 89 8d ec aa fe ff 8b 95 ec aa fe ff 3b 95 f4 aa fe ff 73 29 8b 85 ec aa fe ff c1 e0 00 8d 8d f8 aa fe ff 0f b6 14 08 f7 da 8b 85 ec aa fe ff c1 e0 00 8d 8d f8 aa fe ff 88 14 08 eb ba}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DCRat_RPX_2147845431_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DCRat.RPX!MTB"
        threat_id = "2147845431"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c6 85 f8 aa fe ff e8 c6 85 f9 aa fe ff 88 c6 85 fa aa fe ff f7 c6 85 fb aa fe ff 00 c6 85 fc aa fe ff 00 c6 85 fd aa fe ff 88 c6 85 fe aa fe ff f7 c6 85 ff aa fe ff 00 c6 85 00 ab fe ff 00 c6 85 01 ab fe ff 00 c6 85 02 ab fe ff 97 c6 85 03 ab fe ff f2 c6 85 04 ab fe ff a3 c6 85 05 ab fe ff 74}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DCRat_RE_2147847336_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DCRat.RE!MTB"
        threat_id = "2147847336"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c8 0f b6 c1 8a 84 05 ?? fe ff ff 32 86 ?? ?? ?? ?? 88 86 ?? ?? ?? ?? c7 45 fc ff ff ff ff 8b 85 ?? fe ff ff 8b 8d ?? fe ff ff 46 e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DCRat_B_2147851743_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DCRat.B!MTB"
        threat_id = "2147851743"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "SOFTWARE\\Microsoft\\Windows Defender\\Exclusions" ascii //weight: 2
        $x_2_2 = "ExclusionProcess" ascii //weight: 2
        $x_2_3 = "cn5+ekQ5OTtDPTg8PT04PkM4PDpDOQ==" ascii //weight: 2
        $x_2_4 = "vmsrvc.sys" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DCRat_C_2147890523_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DCRat.C!MTB"
        threat_id = "2147890523"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {f7 f6 89 d1 8b ?? e4 8b ?? f4 01 d0 0f b6 00 89 c2 89 c8 31 d0 89 c1 8b ?? e4 8b ?? f4 01 d0 88 08 83 45 f4}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DCRat_GXZ_2147903167_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DCRat.GXZ!MTB"
        threat_id = "2147903167"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {13 c0 03 dd 8b 6c 24 ?? 13 d0 0f ac d3 ?? 8b d1 6b c3 ?? 2b d0 8a 82 ?? ?? ?? ?? 30 81}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DCRat_NC_2147903322_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DCRat.NC!MTB"
        threat_id = "2147903322"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cktOgAu20kZfM6aZTzWLhk6dDlzbKi.vbe" ascii //weight: 1
        $x_1_2 = "ecktOgAu20kZfM6aZTzWLhk6dDlzbKi.vbe" ascii //weight: 1
        $x_1_3 = "WLhk6dDlzbKi.vbe" ascii //weight: 1
        $x_1_4 = "serverWebBroker.exe" ascii //weight: 1
        $x_1_5 = "DrivermonitorCommon" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DCRat_ASFU_2147906676_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DCRat.ASFU!MTB"
        threat_id = "2147906676"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {8b 4d 08 03 4d fc 88 01 8b 55 08 03 55 fc 0f b6 02 35 ?? ?? ?? ?? 8b 4d 08 03 4d fc 88 01 e9}  //weight: 4, accuracy: Low
        $x_1_2 = "XiAnA91klaK" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DCRat_MQ_2147907303_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DCRat.MQ!MTB"
        threat_id = "2147907303"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {74 0f b0 01 eb 30 85 ff 74 03 c6 07 01 32 c0 eb 25}  //weight: 5, accuracy: High
        $x_5_2 = ".vbe" ascii //weight: 5
        $x_1_3 = "DarkCrystal RAT" wide //weight: 1
        $x_1_4 = "DCrat" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_DCRat_D_2147907981_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DCRat.D!MTB"
        threat_id = "2147907981"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {32 cb 52 5a c1 f2 ?? d0 c9 f6 d9 80 c1 ?? 80 f1 ?? 32 d9 c1 ca ?? 02 d2 0f be c2}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DCRat_SOL_2147922847_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DCRat.SOL!MTB"
        threat_id = "2147922847"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {e8 11 09 00 00 83 c4 04 eb 02 33 c0 57 ff 75 f8 89 45 fc 50 89 7e 10 89 5e 14 e8 6a 16 00 00 8b 5d fc 83 c4 0c 8b 45 f4 c6 04 1f 00 83 f8 10 72 29 8d 48 01 8b 06}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DCRat_MPX_2147928219_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DCRat.MPX!MTB"
        threat_id = "2147928219"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {2b d1 83 f2 19 8b 85 ?? ?? ?? ?? 0f af 50 04 8b 8d 4c fc ff ff 69 41 04 38 01 00 00 2b d0 8b 8d ?? ?? ?? ?? 89 11 8b 95 4c fc ff ff 89 95 ?? ?? ?? ?? 52 52 83 c4 04 eb}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DCRat_MX_2147947137_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DCRat.MX!MTB"
        threat_id = "2147947137"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 7d 08 8b c7 c1 f8 05 8d 34 85 60 3f 42 00 8b 06 83 e7 1f c1 e7 06 03 c7 8a 58 24 02 db d0 fb}  //weight: 1, accuracy: High
        $x_1_2 = "libGLESv2.dll" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

