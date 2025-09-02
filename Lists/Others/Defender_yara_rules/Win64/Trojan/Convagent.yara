rule Trojan_Win64_Convagent_AD_2147782130_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Convagent.AD!MTB"
        threat_id = "2147782130"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {48 89 5c 24 08 48 89 74 24 10 48 89 7c 24 18 4c 89 64 24 20 55 41 56 41 57 48 8d ac 24 d0 fe ff ff 48 81 ec 30 02 00 00 48 8b 05 51 5f 00 00 48 33 c4 48 89 85 20 01 00 00 bf 46 9c 00 00 c7 85 f0 00 00 00 18 00 21 00 8b df c7 85 f4 00 00 00 70 00 0d 00 c7 85 f8 00 00 00 bb 00 ab 00 c7 44 24 30 b3}  //weight: 10, accuracy: High
        $x_3_2 = "OpenDodgem" ascii //weight: 3
        $x_3_3 = "NotifyBullock64" ascii //weight: 3
        $x_3_4 = "GetThreadPriorityBoost" ascii //weight: 3
        $x_3_5 = "WorkInhalator" ascii //weight: 3
        $x_3_6 = "Ayer" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Convagent_BO_2147829152_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Convagent.BO!MTB"
        threat_id = "2147829152"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "144.172.83.13/Agent64.bin" ascii //weight: 5
        $x_5_2 = "rookbolin.net/Agent64.bin" ascii //weight: 5
        $x_5_3 = "38.108.119.121/Agent64.bin" ascii //weight: 5
        $x_1_4 = "ConvertBmp" ascii //weight: 1
        $x_1_5 = "ConvertJpg" ascii //weight: 1
        $x_1_6 = "ConvertTiff" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 3 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_Convagent_SPS_2147847222_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Convagent.SPS!MTB"
        threat_id = "2147847222"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/q /c sc.exe sdset msdtc \"D:(A;;DCLCWPDTSDCC;;;IU)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)\" & sc stop msdtc & takeown /F C:\\ProgramData\\oci.txt" ascii //weight: 1
        $x_1_2 = "/q /c REG ADD HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\MSDTC\\MTxOCI /v \"OracleOciLib\" /t REG_SZ /d \"../../ProgramData/oci.txt\" /f" ascii //weight: 1
        $x_1_3 = "cmd /c schtasks /create /sc HOURLY /TN \"MicroSoft\\Windows\\AppID\\KeepMsdtc\" /TR \"cmd /c sc config msdtc start= auto && sc start msdtc\" /ru system /f" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Convagent_CRHW_2147847765_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Convagent.CRHW!MTB"
        threat_id = "2147847765"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 b9 04 00 00 00 41 b8 00 10 00 00 8b d6 48 8b cb ff 15 ?? ?? ?? ?? 48 85 c0 74 20 4c 8d 4d 04 41 b8 04 01 00 00 8b d6 48 8b cb ff 15 ?? ?? ?? ?? 85 c0 74 ?? b8 01 00 00 00 eb}  //weight: 1, accuracy: Low
        $x_1_2 = {68 74 74 70 3a 2f 2f 34 35 2e 32 30 34 2e 37 31 2e 31 33 33 2f [0-31] 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_3 = {68 74 74 70 3a 2f 2f 34 35 2e 32 30 34 2e 37 31 2e 31 33 33 2f [0-31] 2e 64 6c 6c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Convagent_CRHY_2147847776_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Convagent.CRHY!MTB"
        threat_id = "2147847776"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "422db991-42b2-4702-b6fb-c5c3fb94c169" ascii //weight: 1
        $x_1_2 = "7e4190ab-a183-f7de-bd5a-12273c88116f" ascii //weight: 1
        $x_1_3 = "1dda6a36-4ad3-5683-6c05-f6b970d1c5d1" ascii //weight: 1
        $x_1_4 = "9a5f21be-5e99-00a3-ea64-09442b7333de" ascii //weight: 1
        $x_1_5 = "dc3f152e-6ea0-cfb4-352c-4f79df6c0f35" ascii //weight: 1
        $x_1_6 = "5ace7675-2f0c-b5de-1ce7-bd7a1fcd3e15" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Convagent_RF_2147890028_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Convagent.RF!MTB"
        threat_id = "2147890028"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Go build ID: \"v1kga1LUcgRyO0Zvvzn0/9iKKAfyHByOKTWGgdQIL/QKhnXcChtCeC0Pn3m5s0/VObPL1hkuIcjIcSzUbdS" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Convagent_MB_2147892756_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Convagent.MB!MTB"
        threat_id = "2147892756"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {33 d2 48 8b 44 24 28 b9 20 00 00 00 48 f7 f1 48 8b c2 48 8b 0d ?? ?? ?? ?? 0f b6 04 01 48 8d 0d ?? ?? ?? ?? 48 8b 54 24 28 0f b6 0c 11 33 c8 8b c1 48 8b 4c 24 28 48 8b 54 24 48 48 03 d1 48 8b ca 88 01 eb}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Convagent_DS_2147895071_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Convagent.DS!MTB"
        threat_id = "2147895071"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4c 89 7c 24 28 44 89 7c 24 20 45 33 c9 4d 8b c6 33 d2 33 c9 ff 15 [0-4] 48 8b d8 48 85 c0 0f 84 [0-4] ba ff ff ff ff 48 8b c8 ff 15 [0-4] 48 8b cb ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b 7d c8 48 2b df 48 c1 fb 03 41 b9 40 00 00 00 41 b8 00 10 00 00 48 8b d3 33 c9 ff 15 [0-4] 4c 8b f0 48 85 c0 0f 84}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Convagent_NG_2147895471_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Convagent.NG!MTB"
        threat_id = "2147895471"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0f 84 7d 01 00 00 8b 16 48 8b 00 48 c7 04 d0 ?? ?? ?? ?? e9 f9 fe ff ff 45 31 c0 ba ?? ?? ?? ?? 48 8d 0d 87 f4 09 00 e8 6f 22 00 00 81 38 ?? ?? ?? ?? 48 89 05 da 7c 0c}  //weight: 5, accuracy: Low
        $x_1_2 = "powershell -ep bypass -w hidden -e" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Convagent_CP_2147899924_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Convagent.CP!MTB"
        threat_id = "2147899924"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 89 f0 49 29 c0 48 89 c1 ba ?? ?? ?? ?? e8 ?? ?? ?? ?? 48 85 c0 74 ?? 8b 08 31 f9 8b 50 ?? 44 31 f2 09 ca 74 ?? 48 ff c0 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Convagent_NC_2147900476_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Convagent.NC!MTB"
        threat_id = "2147900476"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {40 32 ff 40 88 7c 24 ?? e8 6f ec ff ff 8a d8 8b 0d f3 d4 02 00 83 f9 ?? 0f 84 1d 01 00 00 85 c9 75 4a}  //weight: 5, accuracy: Low
        $x_1_2 = "A2ma6Aw" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Convagent_RC_2147902105_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Convagent.RC!MTB"
        threat_id = "2147902105"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {44 88 db 80 f3 ff 80 e3 01 40 b6 01 40 88 f7 40 80 f7 01 45 88 de 41 20 fe 44 08 f3 40 88 f7}  //weight: 5, accuracy: High
        $x_1_2 = {6f 75 74 2e 64 6c 6c 00 78 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Convagent_SPGE_2147902438_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Convagent.SPGE!MTB"
        threat_id = "2147902438"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4c 8b c9 33 c9 8b d1 8b c1 4d 8b c1 66 41 83 38 5c 0f 44 c2 66 41 39 08 74 08 ff c2 49 83 c0 02}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Convagent_RZ_2147914030_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Convagent.RZ!MTB"
        threat_id = "2147914030"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 c7 48 8b 75 10 48 c7 c1 ?? ?? ?? 00 48 c1 e9 03 f3 48 a5 48 8d 45 e8 48 83 ec 20 48 c7 c1 ?? ?? ?? 00 48 8b 55 10 4c 8b 45 10 49 89 c1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Convagent_CCJB_2147915025_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Convagent.CCJB!MTB"
        threat_id = "2147915025"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 3b 66 10 76 ?? 55 48 89 e5 48 83 ec 30 48 8d 05 ?? ?? ?? ?? bb ?? 01 00 00 e8 ?? ?? ?? ?? 90 48 85 c9 74 ?? 31 c0 31 db 48 89 d9 48 83 c4 30 5d c3 48 8d 0d ?? ?? ?? ?? bf 01 00 00 00 31 f6 49 c7 c0 ff ff ff ff e8 ?? ?? ?? ?? 48 83 c4 30 5d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Convagent_ARA_2147915122_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Convagent.ARA!MTB"
        threat_id = "2147915122"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "\\AntiReverseTest\\" ascii //weight: 2
        $x_2_2 = "-WindowStyle Hidden -PassThru" ascii //weight: 2
        $x_2_3 = "start /b PowerShell.exe" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Convagent_TPAA_2147918098_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Convagent.TPAA!MTB"
        threat_id = "2147918098"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {ff c2 48 63 ca 0f b6 04 19 88 04 1f 44 88 0c 19 0f b6 0c 1f 49 03 c9 0f b6 c1 0f b6 04 18 41 30 02 49 ff c2 49 8b c2 49 2b c6 49 3b c3 72 a3}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Convagent_ASJ_2147920617_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Convagent.ASJ!MTB"
        threat_id = "2147920617"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 54 24 08 03 14 24 33 54 24 04 89 54 24 ?? 8b 54 24 1c e9}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Convagent_GZN_2147926485_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Convagent.GZN!MTB"
        threat_id = "2147926485"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {41 8b f6 33 d2 b9 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 48 8b d8 48 83 f8 ?? ?? ?? c7 45 ?? 38 02 00 00 48 8d 55 ?? 48 8b c8 ff 15}  //weight: 4, accuracy: Low
        $x_2_2 = {48 8b cb ff 15 ?? ?? ?? ?? 85 c0 75}  //weight: 2, accuracy: Low
        $x_1_3 = "data\\zcrxdebug.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Convagent_NAC_2147926643_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Convagent.NAC!MTB"
        threat_id = "2147926643"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "/C sc create XblGame binPath=\"C:\\Users\\Public\\data\\mdwslp.exe\" start= auto" ascii //weight: 2
        $x_1_2 = "/C sc start XblGame" ascii //weight: 1
        $x_1_3 = "C:\\Users\\Public\\data\\zcrxdebug.txt" ascii //weight: 1
        $x_1_4 = "C:\\Windows\\System32\\signtool.exe" ascii //weight: 1
        $x_1_5 = "C:\\Users\\Public\\data\\mdwslp.exe" ascii //weight: 1
        $x_1_6 = {44 00 3a 00 5c 00 77 00 6f 00 72 00 6b 00 5c 00 5f 00 5f 00 63 00 68 00 72 00 6f 00 6d 00 65 00 5f 00 65 00 78 00 5f 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 5c 00 5f 00 5f 00 6d 00 79 00 5f 00 73 00 72 00 63 00 5c 00 73 00 72 00 63 00 5c 00 5f 00 52 00 65 00 6c 00 65 00 61 00 73 00 65 00 5c 00 [0-31] 2e 00 70 00 64 00 62 00}  //weight: 1, accuracy: Low
        $x_1_7 = {44 3a 5c 77 6f 72 6b 5c 5f 5f 63 68 72 6f 6d 65 5f 65 78 5f 69 6e 73 74 61 6c 6c 5c 5f 5f 6d 79 5f 73 72 63 5c 73 72 63 5c 5f 52 65 6c 65 61 73 65 5c [0-31] 2e 70 64 62}  //weight: 1, accuracy: Low
        $x_1_8 = "powershell -Command \"New-SelfSignedCertificate -Type CodeSigning -Subject 'CN=aaa' -KeyUsage DigitalSignature" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 6 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_Convagent_AMCW_2147929517_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Convagent.AMCW!MTB"
        threat_id = "2147929517"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 6e 74 69 63 68 65 61 74 00 42 69 72 64 00 43 61 74 00 43 72 61 62 00 44 6f 67 00 44 75 63 6b 00 45 6c 65 70 68 61 6e 74 00 48 6f 70 65 00 4b 6e 69 67 68 74 00 4d 6f 6c 64 6f 76 61 00 4f 6d 61 72 00 50 65 6e 67 75 69 6e 00 57 6f 6c 66 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 00 44 6c 6c 47 65 74 43 6c 61 73 73 4f 62 6a 65 63 74 00 44 6c 6c 4d 61 69 6e 00 44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 00 44 6c 6c 55 6e 72 65 67 69 73 74 65 72 53 65 72 76 65 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Convagent_PMM_2147932482_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Convagent.PMM"
        threat_id = "2147932482"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Convagent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {88 85 4f 03 00 00 0f b6 85 4f 03 00 00 83 f0 01 84 c0 74 0a bb 01 00 00 00 e9}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Convagent_CCJT_2147933440_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Convagent.CCJT!MTB"
        threat_id = "2147933440"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 c2 41 2a c0 f6 d0 41 fe c0 48 ff c1 30 41 ff 44 3a c2 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Convagent_ARAZ_2147937060_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Convagent.ARAZ!MTB"
        threat_id = "2147937060"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "smessageFromHell.txt" ascii //weight: 2
        $x_2_2 = "Nojan" ascii //weight: 2
        $x_2_3 = "NEVER open files from strangers" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Convagent_A_2147939483_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Convagent.A!MTB"
        threat_id = "2147939483"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4d 8b ad d8 03 00 00 49 83 ef 01 73 f3 6a 01 58 48 89 85 c0 01 00 00 45 31 ff 45 31 c0 eb 29}  //weight: 1, accuracy: High
        $x_1_2 = "Convert]::FromBase64String(" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Convagent_GTM_2147939771_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Convagent.GTM!MTB"
        threat_id = "2147939771"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {64 65 2e 0d ?? ?? ?? ?? 00 00 00 00 00 00 27 33 c6 ce 63 52 ?? 9d 63 52 ?? 9d 63 52 ?? 9d 6a 2a 3b 9d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Convagent_NL_2147944294_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Convagent.NL!MTB"
        threat_id = "2147944294"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {48 83 ec 60 48 8d 6c 24 ?? 48 89 4d f0 48 89 55 f8 48 8d 45 f0 48 89 45 c0 48 c7 45 c8 01 00 00 00 48 c7 45 d0 08 00 00 00 0f 57 c0 0f 11 45 d8 4c 8d 05 28 34 11 00 48 8d 4d c0 31 d2 e8 0d ff ff ff}  //weight: 2, accuracy: Low
        $x_1_2 = {8b 45 f8 48 8b 50 08 48 85 d2 74 0d 4c 8b 40 10 48 8b 4d e8 e8 79 4c ad ff ba ?? 00 00 00 41 b8 ?? 00 00 00 48 8b 4d e0 e8 65 4c ad ff 31 c0 48 83 c4 48 5e 5d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Convagent_NR_2147945688_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Convagent.NR!MTB"
        threat_id = "2147945688"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {48 c7 85 b8 00 00 00 1f 00 00 00 0f 10 05 a3 bf 02 00 0f 11 00 f2 0f 10 05 a8 bf 02 00 f2 0f 11 40 10 0f b7 0d a4 bf 02 00 66 89 48 18 0f b6 0d 9b bf 02 00 88 48 1a c6 40 1b 00 80 3d 33 2c 04 00 00 0f 84 93 00 00 00}  //weight: 2, accuracy: High
        $x_1_2 = "WriteProcessMemory of DLL path to remote address" ascii //weight: 1
        $x_1_3 = "DLL injected" ascii //weight: 1
        $x_1_4 = "DLL decryption tasks to complete" ascii //weight: 1
        $x_1_5 = "chrome_inject.exe" wide //weight: 1
        $x_1_6 = "chrome_decrypt.dll" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Convagent_ARAX_2147945733_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Convagent.ARAX!MTB"
        threat_id = "2147945733"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {f7 e9 c1 fa 04 8b c2 c1 e8 1f 03 d0 0f be c2 6b d0 36 0f b6 c1 2a c2 04 38 41 30 00 ff c1 4d 8d 40 01 83 f9 0f 7c d4}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Convagent_MX_2147947636_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Convagent.MX!MTB"
        threat_id = "2147947636"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 89 78 10 48 c7 40 18 0f 00 00 00 40 88 38 48 8d 54 24 40 66 48 0f 7e c1 66 0f 6f c1 66 0f 73 d8 08 66 48 0f 7e c0 48 83 f8 0f 48 0f 47 d1 66 49 0f 7e c8 48 8d 8d 50 01}  //weight: 1, accuracy: High
        $x_1_2 = "discord.com/api/webhooks" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Convagent_GVB_2147949246_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Convagent.GVB!MTB"
        threat_id = "2147949246"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "://194.26.192.94:7777/blacklist" ascii //weight: 2
        $x_1_2 = ".exehijacked" ascii //weight: 1
        $x_1_3 = "chacha20" ascii //weight: 1
        $x_1_4 = "File saved to: " ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Convagent_AHB_2147949262_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Convagent.AHB!MTB"
        threat_id = "2147949262"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "35"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {66 44 0f d6 bc 24 10 01 00 00 c6 44 24 37 00 44 0f 11 bc 24 e0 00 00 00 44 0f 11 bc 24 f0 00 00 00 44 0f 11 bc 24 00 01 00 00 48 c7 84 24 e8 00 00 00 ?? 00 00 00 48 8d 15}  //weight: 20, accuracy: Low
        $x_10_2 = {48 89 44 24 78 48 89 5c 24 60 48 89 4c 24 68 44 0f 11 7c 24 38 44 0f 11 7c 24 48 48 8d 44 24 38 bb ?? 00 00 00 48 89 d9 e8}  //weight: 10, accuracy: Low
        $x_5_3 = "yEvDbFtSaxX58PKud1_R/S-QOuT3xil3h78nB5S3F/kzV00x19StYII30di6uc/mhCUpRZcuBqK_lOWxmQ_" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Convagent_AHC_2147951083_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Convagent.AHC!MTB"
        threat_id = "2147951083"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "35"
        strings_accuracy = "High"
    strings:
        $x_20_1 = {48 c7 84 24 70 01 00 00 2e 00 00 00 48 c7 84 24 78 01 00 00 64 00 00 00 48 c7 84 24 80 01 00 00 6c 00 00 00 48 c7 84 24 88 01 00 00 6c 00 00 00 48 8d 05}  //weight: 20, accuracy: High
        $x_10_2 = {48 c7 84 24 18 03 00 00 63 00 00 00 48 c7 84 24 20 03 00 00 65 00 00 00 48 c7 84 24 28 03 00 00 73 00 00 00 48 c7 84 24 30 03 00 00 41 00 00 00 48 8d 05}  //weight: 10, accuracy: High
        $x_5_3 = "main.getObfuscatedShellcode" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

