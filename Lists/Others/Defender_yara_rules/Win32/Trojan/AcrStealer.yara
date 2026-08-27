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

