rule Trojan_Win64_ClipBanker_Z_2147795870_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ClipBanker.Z!MTB"
        threat_id = "2147795870"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "lt_value_clipperdefault_value_clP" ascii //weight: 1
        $x_1_2 = "bitcoincash:qrtq07jfhk39j6ydd9fc5ya30ndkka4sku9cf6wsq90" ascii //weight: 1
        $x_1_3 = "default_value_clippert1LBf6zWdVYz9oN1Puctivrt8CLk6kburAP" ascii //weight: 1
        $x_1_4 = "MicrosoftWindowsStart MenuProgramsStartupupdater.lnk" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ClipBanker_DG_2147809231_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ClipBanker.DG!MTB"
        threat_id = "2147809231"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "19"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {48 83 ec 30 48 8b f9 49 8b f0 48 8b 49 10 4c 8b 47 18 49 8b c0 48 2b c1 48 3b f0 77 3f 48 89 5c 24 40 48 8d 04 31 48 89 47 10 48 8b c7 49 83 f8 10 72 03}  //weight: 10, accuracy: High
        $x_3_2 = "Application Data\\Clipper" ascii //weight: 3
        $x_3_3 = "BTC Clipper.pdb" ascii //weight: 3
        $x_3_4 = "bitcoincash|bchreg|bchtest" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ClipBanker_DG_2147809231_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ClipBanker.DG!MTB"
        threat_id = "2147809231"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "[13][a-km-zA-HJ-NP-Z1-9]{25,34}" ascii //weight: 3
        $x_3_2 = "APPDATA" ascii //weight: 3
        $x_3_3 = "\\Windowslib.exe" ascii //weight: 3
        $x_3_4 = "3E9FtiBAwPxbFfmhw7bNMfmSysrbcKgXNC" ascii //weight: 3
        $x_3_5 = "HidenProces.pdb" ascii //weight: 3
        $x_3_6 = "-foobar" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ClipBanker_AHL_2147817574_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ClipBanker.AHL!MTB"
        threat_id = "2147817574"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 06 01 1e 48 83 c6 04 ff c9 eb 0f 00 85 c9 74}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 06 48 ff c6 88 07 48 ff c7 bb 02 00 00 00 00 d2 75 [0-9] 73}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 45 f4 ff c0 89 45 f4 81 7d f4 80 00 00 00 74 ?? 8b 45 10 89 83 c3 18 33 18 ff 45 10 48 ff c3 eb}  //weight: 1, accuracy: Low
        $x_1_4 = {fe 0f 48 ff c7 ff c9 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ClipBanker_A_2147829073_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ClipBanker.A!MTB"
        threat_id = "2147829073"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\b[A-Z0-9]{56}" wide //weight: 1
        $x_1_2 = "\\bt1[0-9A-z]{33}" wide //weight: 1
        $x_1_3 = "\\baddr1[a-z0-9]+" wide //weight: 1
        $x_1_4 = "\\b0x[a-fA-F0-9]{40}" wide //weight: 1
        $x_1_5 = "\\bT[a-zA-Z0-9]{28,33}" wide //weight: 1
        $x_1_6 = "\\b(bnb)([a-z0-9]{39})" wide //weight: 1
        $x_1_7 = "\\bltc1[a-z0-9]{39,59}" wide //weight: 1
        $x_1_8 = "\\bA[A-Z][1-9A-z]{32,34}" wide //weight: 1
        $x_1_9 = "\\bronin:[a-fA-F0-9]{40}" wide //weight: 1
        $x_1_10 = "\\bX[1-9A-HJ-NP-Za-km-z]{33}" wide //weight: 1
        $x_1_11 = "\\b1[a-km-zA-HJ-NP-Z1-9]{25,35}" wide //weight: 1
        $x_1_12 = "\\b3[a-km-zA-HJ-NP-Z1-9]{25,35}" wide //weight: 1
        $x_1_13 = "\\b[M][a-km-zA-HJ-NP-Z1-9]{26,33}" wide //weight: 1
        $x_1_14 = "\\b[L][a-km-zA-HJ-NP-Z1-9]{26,33}" wide //weight: 1
        $x_1_15 = "\\b[48][0-9AB][1-9A-HJ-NP-Za-km-z]{93}" wide //weight: 1
        $x_1_16 = "\\bD{1}[5-9A-HJ-NP-U]{1}[1-9A-HJ-NP-Za-km-z]{32}" wide //weight: 1
        $x_1_17 = "\\b((bitcoincash|bchreg|bchtest):)?(q|p)[a-z0-9]{41}" wide //weight: 1
        $x_1_18 = "\\br[rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz]{24,34}" wide //weight: 1
        $x_1_19 = "steamcommunity[.]com/tradeoffer/new/[?]partner=[0-9]{9}&token=[A-z0-9_]{8}" wide //weight: 1
        $x_1_20 = "\\b(bc(0([ac-hj-np-z02-9]{39}|[ac-hj-np-z02-9]{59})|1[ac-hj-np-z02-9]{8,87}))" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ClipBanker_EB_2147831521_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ClipBanker.EB!MTB"
        threat_id = "2147831521"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "md2WithRSAEncryption" ascii //weight: 1
        $x_1_2 = "WsP/Vycd5eiHgC0WhpYMwskAjWF6ha5cQ1zwNEheUy0=" ascii //weight: 1
        $x_1_3 = "Please Select Bot" ascii //weight: 1
        $x_1_4 = "Si-paling-umberela\\Growtopia MultiBot" ascii //weight: 1
        $x_1_5 = "project-umbrella.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ClipBanker_RA_2147831522_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ClipBanker.RA!MTB"
        threat_id = "2147831522"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Realtek.exe" ascii //weight: 1
        $x_1_2 = "(bc1)[a-zA-HJ-NP-Z0-9]{39}$" ascii //weight: 1
        $x_1_3 = "bnb1[0-9a-zA-Z]{38}$)" ascii //weight: 1
        $x_1_4 = "ltc1[0-9A-z]{39}$)" ascii //weight: 1
        $x_1_5 = "addr1q[0-9a-zA-Z]{97}" ascii //weight: 1
        $x_1_6 = "cosmos1[0-9a-zA-Z]{38}$)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ClipBanker_B_2147835156_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ClipBanker.B!MTB"
        threat_id = "2147835156"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {66 83 f8 62 75 74 0f b7 43 02 66 83 f8 63 75 43 66 83 7b 04 31 0f 85 d4 00 00 00 0f b7 43 06 66 83 f8 71 75 12 48 8d 05 14 46 00 00 48 8b 5c 24 30 48 83 c4 20 5f c3}  //weight: 2, accuracy: High
        $x_1_2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ClipBanker_E_2147836288_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ClipBanker.E!MTB"
        threat_id = "2147836288"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {48 8b 9c 24 ?? 00 00 00 48 8b 8c 24 ?? 00 00 00 48 c7 84 24 ?? 00 00 00 00 00 00 00 44 0f 11 bc 24 ?? 00 00 00 31 c0 e8 ?? 04 f4 ff 48 89 84 24 ?? 00 00 00 48 89 5c 24 ?? 48 8d 05 ?? ae 03 00 bb 22 00 00 00 e8 ?? 9c ff ff 48 89 84 24 c0 00 00 00 48 8b 5c 24 ?? 48 8b 8c 24 ?? 00 00 00 48 8b 7c 24 ?? 48 8b 84 24 ?? 00 00 00 0f 1f 44 00 00 e8 ?? 63 fa ff 48 85 c0 7c}  //weight: 2, accuracy: Low
        $x_1_2 = "SetClipboardData" ascii //weight: 1
        $x_1_3 = "0x[a-fA-F0-9]{40}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ClipBanker_F_2147837509_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ClipBanker.F!MTB"
        threat_id = "2147837509"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {48 89 85 a0 04 00 00 c7 85 84 04 00 00 00 00 00 00 48 8d 0d 28 6b 1c 00 e8 e8 57 fc ff 48 8d 15 39 6f 15 00 48 8d 4d 08 e8 c5 24 fc ff 90 48 8d 15 58 6f 15 00 48 8d 4d 48 e8 b4 24 fc ff 90 ba 58 00 00 00 48 8d 8d 90 00 00 00 e8 c8 49 fc ff 41 b8 01 00 00 00 48 8d 15 68 6f 15 00 48 8d 8d 90 00 00 00 e8 ed 29 fc ff 90 ba 58 00 00 00 48 8d 8d 10 01 00 00 e8 9d 49 fc ff 41 b8 01 00 00 00 48 8d 15 5d 6f 15 00 48 8d 8d 10 01 00 00 e8 c2 29 fc ff}  //weight: 2, accuracy: High
        $x_2_2 = {ff 15 6f 7f 1c 00 ff c0 48 98 48 8b d0 b9 40 00 00 00 ff 15 2d 7f 1c 00 48 89 45 28 48 8b 4d 28 ff 15 37 7f 1c 00 48 89 45 68 48 8b 55 48 48 8b 4d 68 ff 15 35 7f 1c 00 48 8b 4d 28 ff 15 13 7f 1c 00 33 c9 ff 15 3b 83 1c 00 ff 15 45 83 1c 00 48 8b 55 28 b9 01 00 00 00 ff 15 16 83 1c 00 ff 15 18 83 1c 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ClipBanker_G_2147837511_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ClipBanker.G!MTB"
        threat_id = "2147837511"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34})src\\main.rs" ascii //weight: 2
        $x_2_2 = "D{1}[5-9A-HJ-NP-U]{1}[1-9A-HJ-NP-Za-km-z]{32}" ascii //weight: 2
        $x_2_3 = "0x[a-fA-F0-9]{40}" ascii //weight: 2
        $x_2_4 = "[LM3][a-km-zA-HJ-NP-Z1-9]{26,33}" ascii //weight: 2
        $x_2_5 = "[48][0-9AB][1-9A-HJ-NP-Za-km-z]{93}" ascii //weight: 2
        $x_2_6 = "X[1-9A-HJ-NP-Za-km-z]{33}" ascii //weight: 2
        $x_2_7 = "r[0-9a-zA-Z]{24,34}" ascii //weight: 2
        $x_2_8 = "nothingbc1BTC" ascii //weight: 2
        $x_2_9 = "BTCDOGEETCLTCXMRDASHRIPPLEbnbBNBaddr1ADATTRXtZCASHdefault_value_clipper]" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ClipBanker_H_2147837856_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ClipBanker.H!MTB"
        threat_id = "2147837856"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34})src\\main.rs" ascii //weight: 2
        $x_2_2 = "D{1}[5-9A-HJ-NP-U]{1}[1-9A-HJ-NP-Za-km-z]{32}" ascii //weight: 2
        $x_2_3 = "0x[a-fA-F0-9]{40}" ascii //weight: 2
        $x_2_4 = "[LM3][a-km-zA-HJ-NP-Z1-9]{26,33}" ascii //weight: 2
        $x_2_5 = "[48][0-9AB][1-9A-HJ-NP-Za-km-z]{93}" ascii //weight: 2
        $x_2_6 = "X[1-9A-HJ-NP-Za-km-z]{33}" ascii //weight: 2
        $x_2_7 = "r[0-9a-zA-Z]{24,34}" ascii //weight: 2
        $x_2_8 = "nothingbc1" ascii //weight: 2
        $x_2_9 = "bnbaddr1Ttdefault_value_clipper]" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ClipBanker_BI_2147838100_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ClipBanker.BI!MTB"
        threat_id = "2147838100"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {34 22 41 80 f0 22 41 80 f1 22 88 44 24 21 33 db 44 88 44 24 24 b1 4e 44 88 4c 24 25 80 f1 22 88 5c 24 28 b2 4b 88 4c 24 22 80 f2 22 48 8d 44 24 21 41 b2 47 88 54 24 23}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ClipBanker_J_2147839034_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ClipBanker.J!MTB"
        threat_id = "2147839034"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {48 89 4c 24 38 48 89 44 24 40 48 8d 44 24 38 48 89 44 24 60 c6 44 24 27 03}  //weight: 2, accuracy: High
        $x_2_2 = {48 89 44 24 48 48 89 5c 24 50 48 89 4c 24 58 48 89 7c 24 28 48 89 74 24 30 c6 44 24 27 01 48 8b 54 24 60 48 8b 02}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ClipBanker_K_2147839989_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ClipBanker.K!MTB"
        threat_id = "2147839989"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0f be 00 88 41 78 8b d0 48 8d 0d 7b 04 03 00 e8 f2 99 00 00 0f be 4b 78 48 85 c0 8b c1 75}  //weight: 2, accuracy: High
        $x_2_2 = "\\stub\\x64\\Release\\stub.pdb" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ClipBanker_L_2147840499_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ClipBanker.L!MTB"
        threat_id = "2147840499"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {48 89 d1 e8 ?? ?? ?? 00 48 89 44 24 28 49 8d 34 04 48 83 f8 0f 76}  //weight: 2, accuracy: Low
        $x_2_2 = "\\b(0x[a-fA-F0-9]{40})" ascii //weight: 2
        $x_2_3 = "\\b(([13]|bc1)[A-HJ-NP-Za-km-z1-9]{27,34})" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ClipBanker_O_2147841132_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ClipBanker.O!MTB"
        threat_id = "2147841132"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {b8 00 5e d0 b2 e8 f0 cd ce ff 90 e8 6a 2e ef ff 48 89 44 24 40 48 89 5c 24 28 e8 fb 6e ff ff 48 89 c1 48 89 df 48 8b 44 24 40 48 8b 5c 24 28 e8}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ClipBanker_RE_2147841708_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ClipBanker.RE!MTB"
        threat_id = "2147841708"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "3MpVeUMobZnoAKRDQvRK7WoV8kPSFCEQjk" ascii //weight: 1
        $x_1_2 = "bc1qn64vxw3m8ge992jpfklvv4e2jq7k34zw9r9nld" ascii //weight: 1
        $x_1_3 = "LNoffeuYXZDWuq5oLQjugsubiFD57HAVMZ" ascii //weight: 1
        $x_1_4 = "BitcoinClipboardMalware-1-master\\btcclipboard\\x64\\Release\\avery.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ClipBanker_R_2147841906_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ClipBanker.R!MTB"
        threat_id = "2147841906"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {48 8d 15 d7 21 00 00 48 8d 8d 40 02 00 00 ff 15 ?? ?? 00 00 48 8d 15 ?? 21 00 00 48 8b f8 48 8d 8d 40 03 00 00 ff 15 ?? 1f 00 00 8b 8d 34 01 00 00 48 8b f0 ff c1 48 63 c9 e8 ?? 01 00 00 4c 63 85 34 01 00 00 4d 8b ce ba 01 00 00 00 48 8b c8 48 8b d8 ff 15 ?? 1f 00 00 4c 63 85 34 01 00 00 4c 8b cf ba 01 00 00 00 48 8b cb ff 15 7d 1f 00 00 48 8b cf ff 15}  //weight: 2, accuracy: Low
        $x_1_2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ClipBanker_S_2147842196_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ClipBanker.S!MTB"
        threat_id = "2147842196"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {48 8b 5c 24 48 48 8b 4c 24 50 48 c7 44 24 48 00 00 00 00 44 0f 11 7c 24 50 31 c0 e8 6b f1 f6 ff e8 06 87 fc ff 48 89 44 24 40 48 89 5c 24 28 48 8b 4c 24 20 48 39 cb 75 27}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ClipBanker_AJ_2147842229_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ClipBanker.AJ!MTB"
        threat_id = "2147842229"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "[48][0-9AB][1-9A-HJ-NP-Za-km-z]{93}" ascii //weight: 2
        $x_2_2 = "GetClipboardSequenceNumber" ascii //weight: 2
        $x_2_3 = "SetClipboardData" ascii //weight: 2
        $x_2_4 = "GetClipboardData" ascii //weight: 2
        $x_2_5 = "EmptyClipboard" ascii //weight: 2
        $x_2_6 = "&& exit" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ClipBanker_I_2147842979_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ClipBanker.I!MTB"
        threat_id = "2147842979"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {48 89 4c 24 30 4c 89 44 24 48 48 89 7c 24 38 41 0f b6 0c 13 41 31 c9 41 0f b6 d9 31 c0}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ClipBanker_C_2147844640_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ClipBanker.C!MTB"
        threat_id = "2147844640"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {48 81 ec 70 02 00 00 48 8d 6c 24 20 48 8d 0d 41 95 13 00 e8 0b ba ff ff ba 20 00 00 00 48 8d 0d 68 78 12 00 e8 e0 88 ff ff 48 8d 15 d4 18 0f 00 48 8d 8d 50 01 00 00 e8 9b 9c ff ff 90}  //weight: 2, accuracy: High
        $x_2_2 = "\\Clipez\\x64\\Debug\\Clipez.pdb" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ClipBanker_C_2147844640_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ClipBanker.C!MTB"
        threat_id = "2147844640"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {33 c9 ff 15 ?? ?? ?? ?? 85 c0 0f 84 ?? ?? ?? ?? b9 01 00 00 00 ff 15 ?? ?? ?? ?? 48 8b d8 48 85 c0 0f 84 ?? ?? ?? ?? 48 8b c8 ff 15 ?? ?? ?? ?? 48 85 c0 0f 84}  //weight: 3, accuracy: Low
        $x_3_2 = "0x581A6F88f87522c69662C75e76253f060C50b198" ascii //weight: 3
        $x_2_3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ClipBanker_N_2147846841_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ClipBanker.N!MTB"
        threat_id = "2147846841"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\Update.exe" ascii //weight: 2
        $x_2_2 = "LOCALAPPDATA" ascii //weight: 2
        $x_2_3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 2
        $x_2_4 = "(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}$" ascii //weight: 2
        $x_2_5 = "0x[a-fA-F0-9]{40}$" ascii //weight: 2
        $x_2_6 = "[LM][a-km-zA-HJ-NP-Z1-9]{26,33}$" ascii //weight: 2
        $x_2_7 = "[4|8]([0-9]|[A-B])(.){93}" ascii //weight: 2
        $x_2_8 = "T[A-Za-z1-9]{33}" ascii //weight: 2
        $x_1_9 = "SetClipboardData" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ClipBanker_U_2147846916_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ClipBanker.U!MTB"
        threat_id = "2147846916"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {48 83 ec 20 48 89 6c 24 18 48 8d 6c 24 18 48 8d 05 65 a2 01 00 0f 1f 44 00 00 e8 ?? ?? f2 ff 48 89 44 24 10 bb 01 00 00 00 e8 ?? ?? f8 ff 31 c0 48 8d 1d 4b 8f 03 00 0f 1f 00 e8 ?? ?? f5 ff 31 c0 48 8d 1d 42 8f 03 00 e8 ?? ?? f5 ff 48 8b 44 24 10 e8 ?? ?? f8 ff 48 8b 6c 24 18 48 83 c4 20}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ClipBanker_AC_2147847635_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ClipBanker.AC!MTB"
        threat_id = "2147847635"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c1 89 05 ?? ?? ?? ?? eb ?? 8b 44 24 ?? 99 83 e2 03 03 c2 83 e0 03 2b c2 8b 0d ?? ?? ?? ?? 03 c8 8b c1 89 44 24 ?? 8b 44 24 ?? 8b 0d ?? ?? ?? ?? 0b c8 8b c1 89 05 ?? ?? ?? ?? 33 d2 8b 44 24 ?? b9 03 00 00 00 f7 f1 8b 0d ?? ?? ?? ?? 03 c8 8b c1 89 44 24 ?? 0f be 05 ?? ?? ?? ?? 85 c0 75}  //weight: 1, accuracy: Low
        $x_1_2 = "Nsu2OdiwodOs2" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ClipBanker_AC_2147847635_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ClipBanker.AC!MTB"
        threat_id = "2147847635"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Go build ID:" ascii //weight: 1
        $x_1_2 = "EH0zSVneZPSuFR11BlR9YppQTVDbh5+16AmcJi4g1z4=" ascii //weight: 1
        $x_1_3 = "GetClipboardData" ascii //weight: 1
        $x_1_4 = "SetClipboardData" ascii //weight: 1
        $x_1_5 = "U7HVewhFgAU7MPSD9EqL9641UbAvyhUE" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ClipBanker_AC_2147847635_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ClipBanker.AC!MTB"
        threat_id = "2147847635"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Copy event detected at {0} (UTC)!" wide //weight: 1
        $x_1_2 = "Clipboard Active Window:" wide //weight: 1
        $x_1_3 = "Clipboard Content:" wide //weight: 1
        $x_1_4 = "WM_CLIPBOARDUPDATE" ascii //weight: 1
        $x_1_5 = "SharpClipboard.exe" ascii //weight: 1
        $x_1_6 = "ClipboardNotification" ascii //weight: 1
        $x_1_7 = "AddClipboardFormatListener" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ClipBanker_RPX_2147848710_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ClipBanker.RPX!MTB"
        threat_id = "2147848710"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {88 45 a2 48 63 c3 0f b6 0c 30 0f b6 c1 34 65 02 c1 88 45 a3 8d 53 02 48 63 c2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ClipBanker_W_2147851022_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ClipBanker.W!MTB"
        threat_id = "2147851022"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {48 8b 05 ce 9b 03 00 48 83 f8 2a 72 ?? 48 83 f8 10 48 c7 05 ?? ?? ?? ?? 2a 00 00 00 48 8b de 48 8d 15 ?? ?? ?? ?? 48 0f 43 1d 8f 9b 03 00 41 b8 2a 00 00 00 48 8b cb e8}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ClipBanker_X_2147851269_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ClipBanker.X!MTB"
        threat_id = "2147851269"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Monero address detected in clipboard" ascii //weight: 2
        $x_2_2 = "Litecoin address detected in clipboard" ascii //weight: 2
        $x_2_3 = "Bitcoin address detected in clipboard" ascii //weight: 2
        $x_2_4 = "Ethereum address detected in clipboard" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ClipBanker_PAAY_2147853148_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ClipBanker.PAAY!MTB"
        threat_id = "2147853148"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 bb 32 c9 bf 4b 49 c1 cb 14 49 f7 d3 8b 4f fc 33 cb 41 8b c3 45 8b c3 c1 c1 02 4f 8d 94 d8 2c 75 30 f8 4c 8d 0c 45 3e 95 2c a9 0f c9 4a 8d 14 95 82 3a 14 9a 49 c1 f0 53 41 50 f7 d9 81 e9 18 a4 35 8f 48 c1 24 24 f6 48 c1 f0 6a 48 01 1c 24 41 81 ca 1c e7 08 b0 f6 da 49 0f c1 c3 31 0c 24 4d 2b ca 5b 49 f7 da 41 f6 db}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ClipBanker_GPAB_2147905961_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ClipBanker.GPAB!MTB"
        threat_id = "2147905961"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {0f b6 3d 89 a9 20 00 31 fe 40 88 34 18 48 ff c3}  //weight: 7, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ClipBanker_AZ_2147906965_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ClipBanker.AZ!MTB"
        threat_id = "2147906965"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "AutoLaunch_7KO45DE4T5F6OJG6NFJP4" ascii //weight: 2
        $x_1_2 = "_ZNKSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE6lengthEv" ascii //weight: 1
        $x_1_3 = "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEixEy" ascii //weight: 1
        $x_1_4 = "_ZNKSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE6substrEyy" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ClipBanker_AY_2147913349_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ClipBanker.AY!MTB"
        threat_id = "2147913349"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}$" ascii //weight: 2
        $x_2_2 = "(?:^[LM3][a-km-zA-HJ-NP-Z1-9]{26,33}$)" ascii //weight: 2
        $x_2_3 = "(?:^0x[a-fA-F0-9]{40}$)" ascii //weight: 2
        $x_2_4 = "(?:^[48][0-9AB][1-9A-HJ-NP-Za-km-z]{93}$)" ascii //weight: 2
        $x_2_5 = "(?:^r[0-9a-zA-Z]{33}$)" ascii //weight: 2
        $x_2_6 = "Silent Miner.pdb" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ClipBanker_GTT_2147928253_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ClipBanker.GTT!MTB"
        threat_id = "2147928253"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "XMRbnb1BNB" ascii //weight: 2
        $x_2_2 = "TRX0x3fETC0xETHt1ZECbc113BTC-_TON" ascii //weight: 2
        $x_2_3 = "bitcoincash|bchreg|bchtest" ascii //weight: 2
        $x_1_4 = "CreateMutex" ascii //weight: 1
        $x_1_5 = "GetClipboardData" ascii //weight: 1
        $x_1_6 = "SetClipboardData" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ClipBanker_ACA_2147928356_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ClipBanker.ACA!MTB"
        threat_id = "2147928356"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 55 c0 48 89 45 c8 eb 0b 48 8d 4d 30 e8 ?? ?? ?? ?? eb 38 48 8b 55 c0 48 8b 4d c8 e8 ?? ?? ?? ?? 48 89 55 b0 48 89 45 b8 eb 00 48 8b 55 b0 48 8b 4d b8 31 c0 41 88 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ClipBanker_AUJ_2147932197_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ClipBanker.AUJ!MTB"
        threat_id = "2147932197"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {30 8c 24 ea 00 00 00 30 8c 24 eb 00 00 00 30 8c 24 ec 00 00 00 30 8c 24 ed 00 00 00 30 8c 24 ee 00 00 00 30 8c 24 ef 00 00 00 32 d1 88 94 24 f0 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = "ChromiumData.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ClipBanker_WQ_2147940103_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ClipBanker.WQ!MTB"
        threat_id = "2147940103"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/panel/gate.php" ascii //weight: 1
        $x_1_2 = "Monitoring clipboard for cryptocurrency addresses" ascii //weight: 1
        $x_1_3 = "wallet. Replacing " ascii //weight: 1
        $x_1_4 = "[INFO] tor.exe found, skipping download" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ClipBanker_ACL_2147941665_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ClipBanker.ACL!MTB"
        threat_id = "2147941665"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {48 8b 4c 24 38 48 8d 44 24 30 48 8d 15 06 9d 01 00 44 8b cb 45 33 c0 89 5c 24 28 48 89 44 24 20 ff 15 ?? ?? ?? ?? 48 8b 4c 24 38 ff 15 ?? ?? ?? ?? b9 50 c3 00 00 ff 15}  //weight: 3, accuracy: Low
        $x_2_2 = {40 53 48 83 ec 40 4c 8d 05 33 9d 01 00 ba 01 00 00 00 33 c9 ff 15 ?? ?? ?? ?? 48 8b d8 48 85 c0}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ClipBanker_NJA_2147942816_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ClipBanker.NJA!MTB"
        threat_id = "2147942816"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Diamotrix" ascii //weight: 2
        $x_1_2 = "TWbAkXq2SupYU6umEVMvxWhAA7t8LyLWJD" ascii //weight: 1
        $x_1_3 = "0x2291d605f6fd3e7e3974d75f7c1cef36aa8e8e3a" ascii //weight: 1
        $x_1_4 = "\\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\\b" ascii //weight: 1
        $x_1_5 = "\\bbitcoincash:[a-zA-HJ-NP-Z0-9]{26,42}\\b" ascii //weight: 1
        $x_1_6 = "1H27c3wZzSebHCYVhfjy4334jFdyM5kHsB" ascii //weight: 1
        $x_1_7 = "GetClipboardData" ascii //weight: 1
        $x_1_8 = "SetClipboardData" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ClipBanker_NJB_2147942834_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ClipBanker.NJB!MTB"
        threat_id = "2147942834"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "Diamotrix" ascii //weight: 2
        $x_1_2 = "bbitcoincash" ascii //weight: 1
        $x_1_3 = {4c 8b c3 33 d2 48 8b c6 48 f7 77 ?? 42 8a 04 0a 32 04 31 41 88 04 30 48 ff c6 48 3b 74 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_ClipBanker_NJC_2147942850_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ClipBanker.NJC!MTB"
        threat_id = "2147942850"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 2
        $x_1_2 = "\\bbitcoincash:[a-zA-HJ-NP-Z0-9]{26,42}\\b" ascii //weight: 1
        $x_1_3 = "GetClipboardData" ascii //weight: 1
        $x_1_4 = "SetClipboardData" ascii //weight: 1
        $x_1_5 = "\\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\\b" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ClipBanker_SX_2147943594_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ClipBanker.SX!MTB"
        threat_id = "2147943594"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {ba 01 00 00 00 33 c9 ff 15 ?? ?? ?? ?? 48 8b d8 48 85 c0 74 ?? ff 15 ?? ?? ?? ?? 3d b7 00 00 00 75 ?? 48 8b cb}  //weight: 10, accuracy: Low
        $x_10_2 = {b9 01 00 00 00 ff 15 ?? ?? ?? ?? 48 8b f8 48 85 c0 74 ?? 48 8b c8 ff 15 ?? ?? ?? ?? 48 85 c0 74 0c 48 8b cf 48 8b f0 ff 15}  //weight: 10, accuracy: Low
        $x_5_3 = "drvoptimcxsq" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

