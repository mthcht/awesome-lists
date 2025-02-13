rule PWS_Win32_Zuten_A_2147600461_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Zuten.gen!A"
        threat_id = "2147600461"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Zuten"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {6a fc 56 ff d7 8b 1d ?? ?? ?? ?? 8d 55 f8 6a 00 52 8d 45 f4 6a 04 50 56 ff d3 81 7d f4 fc fd fe ff 74 10 56 ff 15}  //weight: 5, accuracy: Low
        $x_4_2 = {85 db 74 18 8a 06 8a 0f d2 c0 88 06 46 47 4b 4a 85 d2 75 ec}  //weight: 4, accuracy: High
        $x_1_3 = {6a 04 52 53 c7 45 ?? fc fd fe ff ff d6 53 ff 15}  //weight: 1, accuracy: Low
        $x_1_4 = {6a 04 50 56 ff d3 81 7c 24 ?? fc fd fe ff 74 11 56 ff 15}  //weight: 1, accuracy: Low
        $x_1_5 = {6a 04 52 53 ff d7 8b 44 24 14 6a 02 3d fc fd fe ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*))) or
            ((1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Zuten_B_2147613705_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Zuten.gen!B"
        threat_id = "2147613705"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Zuten"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 6a 40 6a 01 56 ff 15 ?? ?? 00 10 8b 45 08 c6 06 e9 2b c6 6a 01 83 e8 05 89 46 01}  //weight: 1, accuracy: Low
        $x_1_2 = {5f 4c 69 75 4d 61 7a 69 00}  //weight: 1, accuracy: High
        $x_1_3 = {4a 75 6d 70 48 6f 6f 6b 4f 66 66 00 4a 75 6d 70 48 6f 6f 6b 4f 6e 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Zuten_C_2147625316_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Zuten.gen!C"
        threat_id = "2147625316"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Zuten"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 02 57 6a fc [0-32] ff d3 81 7d ?? 1c 4d 5f 23 [0-20] 6a 02 57 6a f8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Zuten_D_2147649811_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Zuten.gen!D"
        threat_id = "2147649811"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Zuten"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8d bd f5 fe ff ff 59 88 9d f4 fe ff ff f3 ab 66 ab aa ff 15}  //weight: 2, accuracy: High
        $x_2_2 = "cachefiletttppp%08X.rtr" ascii //weight: 2
        $x_1_3 = {c6 45 e5 72 c6 45 e6 73 c6 45 e7 49 c6 45 e8 6e c6 45 e9 66 c6 45 ea 6f ff 15}  //weight: 1, accuracy: High
        $x_1_4 = {43 83 fb 14 7c bc 33 db 8d 85 f0 fb ff ff 53 50 8d}  //weight: 1, accuracy: High
        $x_1_5 = "win08%08x.dll" ascii //weight: 1
        $x_1_6 = {c6 85 d0 fd ff ff 78 c6 85 d1 fd ff ff 57 88 9d d2 fd ff ff f3 ab aa 8d 85 c8 fe ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Zuten_OB_2147748023_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Zuten.OB!MTB"
        threat_id = "2147748023"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Zuten"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 04 1f 33 d2 8a 14 37 03 c2 8b 55 ?? 83 c2 ?? 8b ca 33 d2 f7 f1 8a 04 17 88 45 ?? 8d 45 ?? 8b 55 ?? 8b 4d ?? 8a 54 ?? ?? 8a 4d ?? 32 d1 e8 ?? ?? ?? ?? 8b 55 ?? 8d 45 ?? e8 ?? ?? ?? ?? ff 45 ?? ff 4d ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

