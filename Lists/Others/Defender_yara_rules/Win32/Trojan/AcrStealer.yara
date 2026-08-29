rule Trojan_Win32_AcrStealer_DA_2147929756_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AcrStealer.DA!MTB"
        threat_id = "2147929756"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AcrStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "user_pref(\"extensions.webextensions.uuids" ascii //weight: 1
        $x_1_2 = "<discarded>" ascii //weight: 1
        $x_1_3 = "steamcommunity.com" ascii //weight: 1
        $x_1_4 = "CreateToolhelp32Snapshot" ascii //weight: 1
        $x_1_5 = "RmRegisterResources" ascii //weight: 1
        $x_1_6 = "InternetWriteFile" ascii //weight: 1
        $x_1_7 = "RstrtMgr.DLL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AcrStealer_DA_2147929756_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AcrStealer.DA!MTB"
        threat_id = "2147929756"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AcrStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {1d a0 e5 f2 70 83 fb ff 74 29 85 db 74 11 8d 74 26 00 90 ff 14 9d a0 e5 f2 70 83 eb 01 75 f4 c7 04 24 40 7a f2 70 e8 30 99 fd ff 83 c4 18 5b c3 8d 76 00 31 c0 8d b6 00 00 00 00 89 c3 83 c0 01 8b 14 85 a0 e5 f2 70 85 d2 75 f0 eb bd 8d b4 26 00 00 00 00 8d b4 26 00 00 00 00 a1 10 30 0e 71 85 c0 74 07 c3 8d b6 00 00 00 00 c7 05 10 30 0e 71 01 00 00 00 eb 84 90 90 90 90 83 ec 1c 8b 44 24 24}  //weight: 1, accuracy: High
        $x_1_2 = {95 60 17 0e 71 75 05 88 14 08 eb 09 42 81 fa 00 01 00 00 75 e9 41 81 f9 67 f3 04 00 75 d7 89 04 24 e8 71 ff ff ff 83 c4 14 5b 5d c3 90 90 90 55 89 e5 53 8d 5d 0c 83 ec 14 c7 04 24 01 00 00 00 ff 15 3c f0 f2 70 89 5c 24 08 c7 44 24 04 00 20 0e 71 89 04 24}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_AcrStealer_DB_2147975624_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AcrStealer.DB!MTB"
        threat_id = "2147975624"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AcrStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "================== HR Tool Alt" ascii //weight: 1
        $x_1_2 = "================ Finance Alt Tool (no -lm) ================" ascii //weight: 1
        $x_1_3 = "--- Black-Scholes option price (no libm) ---" ascii //weight: 1
        $x_1_4 = "--- Implied volatility (bisection) ---" ascii //weight: 1
        $x_1_5 = "--- Historical VaR / ES from returns file ---" ascii //weight: 1
        $x_1_6 = "--- Max drawdown from equity curve file ---" ascii //weight: 1
        $x_1_7 = "--- 2-asset minimum-variance weights ---" ascii //weight: 1
        $x_1_8 = "--- FX forward pricing (simple interest parity) ---" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_AcrStealer_UNK_2147975991_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AcrStealer.UNK!MTB"
        threat_id = "2147975991"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AcrStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8d 14 40 8d 94 94 d0 02 00 00 03 0c 82 40 83 f8 03 7c ed}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AcrStealer_DC_2147977221_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AcrStealer.DC!MTB"
        threat_id = "2147977221"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AcrStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {04 00 43 8a 2c 03 45 8d 44 24 01 46 0f b6 04 00 47 8a 0c 03 45 8d 44 24 02 41 83 c4 03 46 0f b6 04 00 46 0f b6 24 20 47 8a 04 03 47 8a 34 23 45 89 cc 45 09 c4 41 09 ec 45 08 f4 0f 88 71 fa ff ff 45 89 cc c1 e5 02 41 89 d7 41 c0 ec 04 41 c1 e1 04 41 09 ec 8d 6a 02 46 88 a4 3c 70 01 00 00 45 89 c4 41 c1 e0 06 44 8d 7a 01 41 c0 ec 02 45 09 f0 83 c2 03 45 09 cc 46 88 a4 3c 70 01 00 00 45 89 ec 44 88 84 2c 70}  //weight: 10, accuracy: High
        $x_10_2 = {64 6c 4e 28 64 6c df 29 64 6c b5 26 64 6c 57 2d 64 6c 83 27 64 6c d5 28 64 6c 8d 29 64 6c 90 27 64 6c b6 2c 64 6c 81 2c 64 6c 04 2a 64 6c ae 26 64 6c d0 27 64 6c cb 29 64 6c 11 2d 64 6c dd 26 64 6c f4 29 64 6c ae 26 64 6c 7d 2a 64}  //weight: 10, accuracy: High
        $x_10_3 = {ff 51 25 63 fc c2 ca b9 f3 84 9e 17 a7 ad fa e6 bc f2 40 a4 63 e5 e6 bc f8 47 42 2c e1 f2 d1 17 6b 96 c2 98 d8 45 39 a1 f4 a0 33 eb 2d 81 7d 03 77 16 9e 0f 7c 4a eb e7 8e 9b 7f 1a fe e2 42 e3 4f f5 51 bf 37 68 40 b6 cb ce 5e 31 6b 57 33 ce 2b fd}  //weight: 10, accuracy: High
        $x_10_4 = {7e 0c 8d 1c bf 01 d3 89 dd 0f a4 c5 07 0f a4 d8 07 6a 09 5a f7 e2 0f 10 16 8d 1c ed 00 00 00 00 01 eb 01 da 0f a4 cf 11 c1 e1 11 f3 0f 10 5e 18 f3 0f 10 4e 1c 0f 16 cb 0f c6 ca 42 0f 57 c8 0f 57 d1 0f 11 16 66 0f 70 c1 ee 66 0f 7e c3 31 cb 66 0f 70 c1 ff 66 0f 7e c1 31 f9 89 4e 14 66 0f}  //weight: 10, accuracy: High
        $x_10_5 = {74 3b 8b 4c 84 08 89 ce c1 c6 19 89 cf c1 c7 0e 8b 54 84 3c 31 f7 c1 e9 03 31 f9 89 d6 c1 c6 0f 89 d7 c1 c7 0d 31 f7 c1 ea 0a 03 4c 84 04 03 4c 84 28 31 fa 01 d1 89 4c 84 44 40 eb c0 89 e8 8b 6d 00 8b 70 04 8b 48 08 89 4c 24 10 8b 58 0c 8b 50 10}  //weight: 10, accuracy: High
        $x_10_6 = {59 5a 31 c0 83 fb 05 7c 1d 80 3e 5c 75 18 80 7e 01 3f 75 12 80 7e 02 3f 75 0c 31 c0 80 7e 03 5c 0f 94 c0 c1 e0 02 89 c1 83 c9 02 39 cb 7e 18 80 7c 06 01 3a 75 11 0f b6 0c 0e 83 f9 5c 74 05 83 f9 2f 75 03 83 c8 03 8d 1c 30 43 31 ff 47 0f b6 43 ff 83 f8 2f 74 0b 83 f8 5c 74 06 85 c0 74 21 eb 1a 8a 03 88 44 24 03 c6}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

