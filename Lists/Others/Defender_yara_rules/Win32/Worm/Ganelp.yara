rule Worm_Win32_Ganelp_B_2147645589_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Ganelp.B"
        threat_id = "2147645589"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Ganelp"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 41 65 74 63 72 65 6f 64 73 47 72 64 73 00}  //weight: 1, accuracy: High
        $x_1_2 = {6e 32 6c 72 33 6c 65 6c 64 6b 65 2e 00}  //weight: 1, accuracy: High
        $x_1_3 = {62 72 6f 46 6c 6c 65 47 61 65 00}  //weight: 1, accuracy: High
        $x_1_4 = {62 6c 6f 41 63 6c 6c 6f 47 61 6c 00}  //weight: 1, accuracy: High
        $x_1_5 = {46 53 74 65 65 65 6c 7a 47 69 69 00}  //weight: 1, accuracy: High
        $x_1_6 = {61 6f 65 32 70 74 65 54 68 33 61 6f 72 65 6c 70 6e 68 43 74 6f 6c 53 73 00}  //weight: 1, accuracy: High
        $x_6_7 = {8b f4 8b 95 d0 fe ff ff 52 ff 15 ?? ?? ?? ?? 3b f4 e8 ?? ?? ?? ?? 89 85 cc fe ff ff 83 bd cc fe ff ff 02 0f 85 ?? ?? ?? ?? 8d 85 54 fa ff ff 50 8b 8d d0 fe ff ff 51 e8 ?? ?? ?? ?? 83 c4 08 89 85 c4 fe ff ff 8d 95 54 fa ff ff 89 95 50 fa ff ff 8b 85 d0 fe ff ff 50 8d 8d 60 fe ff ff 51 e8 76 1e 00 00 83 c4 08 6a 00 68 40 75 42 00 8d 95 54 fe ff ff 52 e8}  //weight: 6, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_6_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Ganelp_A_2147646311_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Ganelp.gen!A"
        threat_id = "2147646311"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Ganelp"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0f be 02 83 f8 4d 0f 85 ?? 00 00 00 8b 0d ?? ?? ?? ?? 03 4d fc 0f be 51 05 83 fa 73 0f 85 ?? 00 00 00 a1 ?? ?? ?? ?? 03 45 fc 0f be 48 08 83 f9 74 75 ?? 8b 15 ?? ?? ?? ?? 03 55 fc 0f be 42 0c 83 f8 6e 75 ?? 8b 0d ?? ?? ?? ?? 03 4d fc 0f be 51 0f 83 fa 77 75}  //weight: 3, accuracy: Low
        $x_2_2 = {e9 8c 00 00 00 c7 45 fc 00 00 00 00 eb 09 8b 55 fc 83 c2 01 89 55 fc 83 7d fc 2d 7d 1b 8b 45 fc 0f be 88 ?? ?? ?? ?? 83 f9 2e 75 0a 8b 55 fc c6 82 ?? ?? ?? ?? 5c eb d6}  //weight: 2, accuracy: Low
        $x_1_3 = "bd:ael*nE::" ascii //weight: 1
        $x_1_4 = "GipFAtteFel" ascii //weight: 1
        $x_1_5 = "etnAtentnnocIrCe" ascii //weight: 1
        $x_1_6 = "leeexthEuSlcA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Ganelp_C_2147653132_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Ganelp.C"
        threat_id = "2147653132"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Ganelp"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "bd:ael*nE::" ascii //weight: 1
        $x_1_2 = "gFsomeralPri" ascii //weight: 1
        $x_1_3 = "SaEgVeetuARelx" ascii //weight: 1
        $x_1_4 = {03 4d fc 0f be 51 05 83 fa 73 75 ?? a1 ?? ?? ?? ?? 03 45 fc 0f be 48 08 83 f9 74 75 ?? 8b ?? ?? ?? ?? ?? 03 55 fc 0f be 42 0c 83 f8 6e 75 ?? 8b ?? ?? ?? ?? ?? 03 4d fc 0f be 51 0f 83 fa 77 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Ganelp_AF_2147786315_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Ganelp.AF!MTB"
        threat_id = "2147786315"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Ganelp"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "msg_bankmoney" ascii //weight: 3
        $x_3_2 = "SetProxyCredentials" ascii //weight: 3
        $x_3_3 = "\\Ad\\config.ini" ascii //weight: 3
        $x_3_4 = "actionto=showmoney&areaid=undefined&gameid=" ascii //weight: 3
        $x_3_5 = "BlackMoon RunTime" ascii //weight: 3
        $x_3_6 = "BOGY'S GAME" ascii //weight: 3
        $x_3_7 = "c:\\windows\\friendl.dll" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Ganelp_ACD_2147787531_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Ganelp.ACD!MTB"
        threat_id = "2147787531"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Ganelp"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "TeUPiinhbmoa" ascii //weight: 3
        $x_3_2 = "HHJJOCNNGEAM" ascii //weight: 3
        $x_3_3 = "moUpuCsY" ascii //weight: 3
        $x_3_4 = "EVENT_SINK_AddRef" ascii //weight: 3
        $x_3_5 = "EVENT_SINK_Release" ascii //weight: 3
        $x_3_6 = "EVENT_SINK_QueryInterface" ascii //weight: 3
        $x_3_7 = "+d+k0U.dll.dll" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Ganelp_GZA_2147901682_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Ganelp.GZA!MTB"
        threat_id = "2147901682"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Ganelp"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {83 c4 08 0f be 0d ?? ?? ?? ?? 83 c1 02 88 8d ?? ?? ?? ?? 0f be 15 ?? ?? ?? ?? 83 c2 15 88 95}  //weight: 5, accuracy: Low
        $x_5_2 = {40 00 fe b1 05 00 d4 f2 03 00 d0 f2 03 00}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Ganelp_RV_2147911025_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Ganelp.RV!MTB"
        threat_id = "2147911025"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Ganelp"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 94 83 c0 2f 99 b9 5e 00 00 00 f7 f9 8b 45 08 03 45 98 8a 4c 15 a0 88 08 eb 02}  //weight: 1, accuracy: High
        $x_1_2 = {8b 4d 10 c1 e1 03 39 4d fc 7d 64 8b 45 fc 99 83 e2 07 03 c2 c1 f8 03 8b 55 0c 0f be 04 02 8b 4d fc}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

