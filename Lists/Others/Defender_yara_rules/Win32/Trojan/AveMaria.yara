rule Trojan_Win32_AveMaria_PA_2147745130_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AveMaria.PA!MTB"
        threat_id = "2147745130"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "23"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "AVE_MARIA" ascii //weight: 4
        $x_4_2 = "KLGlog.txt" ascii //weight: 4
        $x_1_3 = "CARD NUMBER:" ascii //weight: 1
        $x_1_4 = "CARDHOLDER NAME:" ascii //weight: 1
        $x_1_5 = "\",KLG:\"" ascii //weight: 1
        $x_1_6 = "\",STL:\"" ascii //weight: 1
        $x_1_7 = "\",AV:\"" ascii //weight: 1
        $x_1_8 = "\",coldwallets:" ascii //weight: 1
        $x_1_9 = "updatebot" ascii //weight: 1
        $x_1_10 = "restartbot" ascii //weight: 1
        $x_1_11 = "getscreen" ascii //weight: 1
        $x_1_12 = "startklg" ascii //weight: 1
        $x_1_13 = "killprocess" ascii //weight: 1
        $x_1_14 = "startasadminexe" ascii //weight: 1
        $x_1_15 = "dXBkYXRlYm90" ascii //weight: 1
        $x_1_16 = "cmVzdGFydGJvdA==" ascii //weight: 1
        $x_1_17 = "Z2V0c2NyZWVu" ascii //weight: 1
        $x_1_18 = "c3RhcnRrbGc=" ascii //weight: 1
        $x_1_19 = "a2lsbHByb2Nlc3M=" ascii //weight: 1
        $x_1_20 = "c3RhcnRhc2FkbWluZXhl" ascii //weight: 1
        $x_1_21 = "c2h1dGRvd25wYw==" ascii //weight: 1
        $x_1_22 = "Z2V0c3Rs" ascii //weight: 1
        $x_1_23 = "aXN3b3Jra2xn" ascii //weight: 1
        $x_1_24 = "ZG93bmxvYWRmaWxl" ascii //weight: 1
        $x_1_25 = "card_number_encrypted" ascii //weight: 1
        $x_1_26 = "credit_cards" ascii //weight: 1
        $x_1_27 = "Phoenixcoin" wide //weight: 1
        $x_1_28 = "Bytecoin" wide //weight: 1
        $x_1_29 = "Luckycoin" wide //weight: 1
        $x_1_30 = "I0coin" wide //weight: 1
        $x_1_31 = "monero-wallet-gui" wide //weight: 1
        $x_1_32 = "Ethereum" wide //weight: 1
        $x_1_33 = "\\Yandex\\YandexBrowser\\" wide //weight: 1
        $x_1_34 = "\\360Browser\\Browser" wide //weight: 1
        $x_1_35 = "\\Sputnik\\Sputnik" wide //weight: 1
        $x_1_36 = "\\CocCoc\\Browser" wide //weight: 1
        $x_1_37 = "\\uCozMedia\\Uran\\" wide //weight: 1
        $x_1_38 = "\\Comodo\\Chromodo\\" wide //weight: 1
        $x_1_39 = "XFxDb21vZG9cXENocm9tb2RvXFxVc2VyIERhdGFcXA==" ascii //weight: 1
        $x_1_40 = "XFxVQ0Jyb3dzZXJcXFVzZXIgRGF0YV9pMThuXFw=" ascii //weight: 1
        $x_1_41 = "XFxVQ0Jyb3dzZXJcXFVzZXIgRGF0YV9lbi1VU1xc" ascii //weight: 1
        $x_1_42 = "XFxVQ0Jyb3dzZXJcXFVzZXIgRGF0YV9ydS1SVVxc" ascii //weight: 1
        $x_1_43 = "XFxCcm9taXVtXFxVc2VyIERhdGFcXA==" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((23 of ($x_1_*))) or
            ((1 of ($x_4_*) and 19 of ($x_1_*))) or
            ((2 of ($x_4_*) and 15 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_AveMaria_DSK_2147745356_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AveMaria.DSK!MTB"
        threat_id = "2147745356"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 57 01 48 30 17 4f 85 c0 7d}  //weight: 1, accuracy: High
        $x_1_2 = {8a 28 47 8a 0a 4b 88 08 40 88 2a 4a eb}  //weight: 1, accuracy: High
        $x_2_3 = {8b 45 f4 03 45 fc 0f be 08 8b 55 e0 0f be 82 ?? ?? ?? ?? 33 c8 8b 55 f4 03 55 fc 88 0a eb}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_AveMaria_AA_2147745410_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AveMaria.AA!MTB"
        threat_id = "2147745410"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "51"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AVE_MARIA" ascii //weight: 1
        $x_1_2 = "XFxDb21vZG9cXENocm9tb2RvXFxVc2VyIERhdGFcXA==" ascii //weight: 1
        $x_1_3 = "\\Black Coding\\RAT+BOT\\WebServer 2.0\\src\\Release\\WebServer.pdb" ascii //weight: 1
        $x_10_4 = "c2h1dGRvd25wYw==" ascii //weight: 10
        $x_10_5 = "cmVzdGFydGJvdA==" ascii //weight: 10
        $x_10_6 = "ZG93bmxvYWRmaWxl" ascii //weight: 10
        $x_10_7 = "Z2V0c2NyZWVu" ascii //weight: 10
        $x_10_8 = "c3RhcnRhc2FkbWluZXhl" ascii //weight: 10
        $x_10_9 = "shutdownpc" ascii //weight: 10
        $x_10_10 = "restartbot" ascii //weight: 10
        $x_10_11 = "downloadfile" ascii //weight: 10
        $x_10_12 = "getscreen" ascii //weight: 10
        $x_10_13 = "startasadminexe" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_10_*) and 1 of ($x_1_*))) or
            ((6 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_AveMaria_PVD_2147748521_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AveMaria.PVD!MTB"
        threat_id = "2147748521"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 44 24 1c 81 c3 47 86 c8 61 ff 4c 24 20 8b 4c 24 18 89 5c 24 14 0f 85 06 00 8b 35}  //weight: 2, accuracy: Low
        $x_2_2 = {8a c1 81 c7 f8 d7 fa 01 02 c0 89 3d ?? ?? ?? ?? 02 c8 8a 44 24 13 f6 d8 c0 e1 02 2a c1 a2 ?? ?? ?? ?? 8b 44 24 28 89 38 06 00 89 35}  //weight: 2, accuracy: Low
        $x_2_3 = {8b 45 f4 0f b6 0c 10 8b 55 f8 0f b6 84 15 d8 d5 ff ff 33 c1 8b 4d f8 88 84 0d d8 d5 ff ff}  //weight: 2, accuracy: High
        $x_1_4 = {8a 0c 32 8b 15 ?? ?? ?? ?? 88 0c 32 8b 4c 24 30 8a 54 01 ff 88 54 24 08 8b 4c 24 08}  //weight: 1, accuracy: Low
        $x_1_5 = {8a 4c 24 14 a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 30 0c 18 8b c6 5b 5e c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_AveMaria_CC_2147754726_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AveMaria.CC!MTB"
        threat_id = "2147754726"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b c1 33 d2 f7 f6 8b 75 f0 8a 04 32 30 04 39 41 8b 75 f8 3b cb 72 e9 8b cf e8 92 fc ff ff 64 8b 0d 30 00 00 00 89 41 08}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AveMaria_XA_2147754959_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AveMaria.XA!MTB"
        threat_id = "2147754959"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {99 f7 bd 74 ff ff ff 89 95 68 ff ff ff 8b 4d 84 03 8d 6c ff ff ff 0f be 09 8b 95 68 ff ff ff 0f be 44 15 8c 33 c8 e8 ?? ?? ?? ?? 8b 4d 84 03 8d 6c ff ff ff 88 01 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AveMaria_AG_2147755288_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AveMaria.AG!MTB"
        threat_id = "2147755288"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 e6 8b c6 c1 ea ?? 8d 0c 92 c1 e1 ?? 2b c1 8a 44 05 ?? 30 86 ?? ?? ?? ?? 46 81 fe}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AveMaria_GV_2147755830_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AveMaria.GV!MTB"
        threat_id = "2147755830"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 11 88 10 eb ?? 8b 45 ?? 03 85 ?? ?? ?? ?? 0f b6 08 8b 95 ?? ?? ?? ?? 33 8c 95 ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 03 85 ?? ?? ?? ?? 88 08 e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AveMaria_GA_2147758513_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AveMaria.GA!MTB"
        threat_id = "2147758513"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 0c d0 f7 d1 8b 55 ?? 03 55 ?? 88 0a [0-32] 8b 45 ?? 83 c0 ?? 89 45 ?? 8b 4d ?? 83 e9 ?? 39 4d [0-37] 8b 55 ?? 83 ea ?? 2b 55 ?? 8b 85}  //weight: 1, accuracy: Low
        $x_1_2 = {0f be 02 8b 8d [0-32] 0f be 54 0d ?? 33 c2 8b 4d ?? 03 4d ?? 88 01 [0-32] 8b 45 ?? 83 c0 ?? 89 45 ?? 8b 4d ?? 3b 8d [0-32] 8b 45 [0-48] 89 95 [0-32] 8b 55 ?? 03 55}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AveMaria_MR_2147770502_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AveMaria.MR!MTB"
        threat_id = "2147770502"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c8 8b 55 [0-2] 03 [0-5] 88 [0-5] eb 40 00 83 [0-3] 89 [0-5] 8b [0-5] 3b [0-5] 7d [0-2] 8b [0-5] 99 f7 [0-5] 89 [0-5] 8b [0-3] 03 [0-5] 0f [0-3] 8b [0-5] 0f}  //weight: 1, accuracy: Low
        $x_1_2 = {83 c0 01 89 85 [0-4] 8b [0-5] 3b [0-5] 7d [0-2] 8b [0-5] 99 f7 [0-5] 89 [0-5] 8b [0-3] 03 [0-5] 0f [0-3] 8b [0-5] 0f [0-4] 33 [0-3] 8b [0-3] 03 [0-5] 88 [0-5] eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_AveMaria_MS_2147775278_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AveMaria.MS!MTB"
        threat_id = "2147775278"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c0 01 89 45 ?? 8b 4d 8c 83 e9 01 39 4d ?? 7f 33 8b 55 8c 83 ea 01 2b 55 ?? 8b 85 [0-4] 8b 0c ?? f7 d1 89 8d [0-4] 83 bd [0-5] 74 0e 8b 55 84 03 55 ?? 8a 85 [0-4] 88 02 eb b9}  //weight: 1, accuracy: Low
        $x_1_2 = {83 c2 01 89 [0-2] 8b [0-2] 3b [0-5] 7d ?? 8b [0-2] 99 f7 [0-5] 89 [0-5] 8b [0-2] 03 [0-2] 0f [0-4] 8b [0-5] 0f [0-4] 33 ?? 8b [0-2] 03 [0-2] 88 10 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AveMaria_2147776447_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AveMaria.MT!MTB"
        threat_id = "2147776447"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AveMaria"
        severity = "Critical"
        info = "MT: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CheckIC.dll" ascii //weight: 1
        $x_1_2 = "RunDlg.dll" ascii //weight: 1
        $x_1_3 = "ShutDownDlg.dll" ascii //weight: 1
        $x_1_4 = "Internet Walker" ascii //weight: 1
        $x_1_5 = "CONTROL.EXE ncpa.cpl" ascii //weight: 1
        $x_1_6 = "System\\CurrentControlSet\\Control\\Keyboard Layouts" ascii //weight: 1
        $x_1_7 = "Software\\Borland\\Delphi\\Locales" ascii //weight: 1
        $x_1_8 = "EAccessViolation" ascii //weight: 1
        $x_1_9 = "EPrivilege" ascii //weight: 1
        $x_1_10 = "VariantChangeTypeEx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AveMaria_BK_2147811608_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AveMaria.BK!MTB"
        threat_id = "2147811608"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 45 90 03 45 9c 0f be 08 8b 95 6c ff ff ff 0f be 44 15 a8 33 c8 8b 55 90 03 55 9c 88 0a eb}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AveMaria_CA_2147815762_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AveMaria.CA!MTB"
        threat_id = "2147815762"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b c1 83 e0 03 8a 44 05 f4 30 81 [0-4] 41 81 f9 05 5a 00 00 72 e8}  //weight: 2, accuracy: Low
        $x_2_2 = "kWy9ncryption" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AveMaria_R_2147823590_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AveMaria.R!MTB"
        threat_id = "2147823590"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "2E4B756B75726967797575757575757575757575757575757575753A" wide //weight: 1
        $x_1_2 = "41707044617461" wide //weight: 1
        $x_1_3 = "575363726970742E7368656C6C" wide //weight: 1
        $x_1_4 = "73656C66" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AveMaria_B_2147824015_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AveMaria.B!MTB"
        threat_id = "2147824015"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {99 f7 bd 6c ff ff ff 89 95 60 ff ff ff 81 7d 90 00 00 00 01 74 1e 8b 45 80 03 45 90 0f be 00 8b 8d 60 ff ff ff 0f be 4c 0d 98 33 c1 8b 4d 80 03 4d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AveMaria_MA_2147827123_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AveMaria.MA!MTB"
        threat_id = "2147827123"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 68 84 00 00 00 6a 02 6a 00 6a 01 68 00 00 00 10 68 58 37 40 00 ff 15 ?? ?? ?? ?? 6a 00 8b f0 8d 85 e8 fb ff ff 50 ff 35 2c 33 40 00 ff 35 54 37 40 00 56 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = "IsProcessorFeaturePresent" ascii //weight: 1
        $x_1_3 = "CreateToolhelp32Snapshot" ascii //weight: 1
        $x_1_4 = "\\TEMP\\ellocnak.xml" wide //weight: 1
        $x_1_5 = "\\WINDOWS\\SYSTEM32\\pkgmgr.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AveMaria_RPM_2147830181_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AveMaria.RPM!MTB"
        threat_id = "2147830181"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 01 f7 d0 85 c0 74 03 88 04 32 83 e9 04 42 81 f9 ?? ?? ?? ?? 7d e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AveMaria_NER_2147830476_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AveMaria.NER!MTB"
        threat_id = "2147830476"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 d2 8b c3 6a 64 5f f7 f7 8a 44 15 98 30 04 0b 43 81 fb 00 e8 03 00 7c e7}  //weight: 1, accuracy: High
        $x_1_2 = "ATLCon" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AveMaria_NEAQ_2147831832_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AveMaria.NEAQ!MTB"
        threat_id = "2147831832"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6a 00 ff d6 8b c7 6a 64 99 59 f7 f9 8a 84 15 30 ff ff ff 30 04 1f 47 81 ff 00 d0 07 00 7c cb}  //weight: 1, accuracy: High
        $x_1_2 = "topkek" ascii //weight: 1
        $x_1_3 = "Ratlthunk.dll" ascii //weight: 1
        $x_1_4 = "IsDebuggerPresent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AveMaria_NEAT_2147832262_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AveMaria.NEAT!MTB"
        threat_id = "2147832262"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8b 8d 7c ff ff ff 03 4d 90 0f be 11 8b 85 60 ff ff ff 0f be 4c 05 98 33 d1 8b 85 7c ff ff ff 03 45 90 88 10 eb 99}  //weight: 5, accuracy: High
        $x_5_2 = {8b 55 90 83 c2 01 89 55 90 8b 45 90 3b 85 64 ff ff ff 7d 53}  //weight: 5, accuracy: High
        $x_3_3 = "IsProcessorFeaturePresent" ascii //weight: 3
        $x_1_4 = "LoadLibraryExA" ascii //weight: 1
        $x_1_5 = "VirtualAlloc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AveMaria_NEBM_2147833295_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AveMaria.NEBM!MTB"
        threat_id = "2147833295"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {74 24 8b 8d 7c ff ff ff 03 4d 90 0f be 11 8b 85 60 ff ff ff 0f be 4c 05 98 33 d1 8b 85 7c ff ff ff 03 45 90 88 10 eb 85}  //weight: 5, accuracy: High
        $x_5_2 = {8b 55 90 83 c2 01 89 55 90 8b 45 90 3b 85 64 ff ff ff 7d 67}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AveMaria_NEBU_2147834187_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AveMaria.NEBU!MTB"
        threat_id = "2147834187"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {74 2a 8b 8d 7c ff ff ff 03 8d 50 ff ff ff 0f be 11 8b 85 4c ff ff ff 0f be 4c 05 84 33 d1 8b 85 7c ff ff ff 03 85 50 ff ff ff 88 10 e9 57 ff ff ff}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AveMaria_NEBV_2147834401_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AveMaria.NEBV!MTB"
        threat_id = "2147834401"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {33 d2 8b c7 6a 64 59 f7 f1 8b 8d 08 fc ff ff 8a 84 15 14 fc ff ff 30 04 0f 47 81 ff 00 d0 07 00 7c ce}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AveMaria_NECE_2147835136_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AveMaria.NECE!MTB"
        threat_id = "2147835136"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {b9 01 00 00 00 d1 e1 8b 95 6c ff ff ff 8a 44 05 f4 88 04 0a b9 01 00 00 00 6b d1 03 b8 01 00 00 00 6b c8 03 8b 85 6c ff ff ff 8a 54 15 f4 88 14 08 8b f4 ff 95 48 ff ff ff}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AveMaria_NEBW_2147835447_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AveMaria.NEBW!MTB"
        threat_id = "2147835447"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "41"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {0f b6 4d ff c1 e1 05 0b c1 88 45 ff 8b 55 f4 03 55 f8 8a 45 ff 88 02 e9 ea fe ff ff}  //weight: 5, accuracy: High
        $x_4_2 = "wshze.cbp" ascii //weight: 4
        $x_4_3 = "darjqkroah.rei" ascii //weight: 4
        $x_4_4 = "lsdmzpuaiz.exe" ascii //weight: 4
        $x_4_5 = "So-Phong.mdb" ascii //weight: 4
        $x_4_6 = "anal cleft" ascii //weight: 4
        $x_4_7 = "itch.dll" ascii //weight: 4
        $x_4_8 = "age of majority.tif" ascii //weight: 4
        $x_4_9 = "terrified" ascii //weight: 4
        $x_4_10 = "Pham Spoken.mp3" ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AveMaria_NECJ_2147835616_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AveMaria.NECJ!MTB"
        threat_id = "2147835616"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "trichromaticism" ascii //weight: 5
        $x_5_2 = "Keliko.bat" ascii //weight: 5
        $x_5_3 = "shampoo.dat" ascii //weight: 5
        $x_5_4 = "normal value.ppt" ascii //weight: 5
        $x_5_5 = "deservedly.png" ascii //weight: 5
        $x_5_6 = "Maonan Spoken.zip" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AveMaria_NECM_2147835908_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AveMaria.NECM!MTB"
        threat_id = "2147835908"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 95 7c ff ff ff 03 95 50 ff ff ff 0f be 02 8b 8d 4c ff ff ff 0f be 54 0d 84 33 c2 8b 8d 7c ff ff ff 03 8d 50 ff ff ff 88 01 eb 98}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AveMaria_BL_2147836642_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AveMaria.BL!MTB"
        threat_id = "2147836642"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 95 7c ff ff ff 03 95 50 ff ff ff 0f be 02 8b 8d 4c ff ff ff 0f be 54 0d 84 33 c2 8b 8d 7c ff ff ff 03 8d 50 ff ff ff 88 01 e9}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AveMaria_NECV_2147836648_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AveMaria.NECV!MTB"
        threat_id = "2147836648"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 8d 94 fb ff ff 03 8d a0 fb ff ff 0f be 11 8b 85 70 fb ff ff 0f be 8c 05 ac fb ff ff 33 d1 8b 85 94 fb ff ff 03 85 a0 fb ff ff 88 10 e9 76 ff ff ff}  //weight: 10, accuracy: High
        $x_5_2 = "explorer.exe.txt" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AveMaria_NECX_2147836978_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AveMaria.NECX!MTB"
        threat_id = "2147836978"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {0f a4 f9 08 99 c1 e7 08 0b ca 0b f8 0f a4 f9 08 0f be 43 01 99 c1 e7 08 0b ca 0b f8 0f be 03 0f a4 f9 08 99 c1 e7 08 56 0b f8}  //weight: 10, accuracy: High
        $x_2_2 = "Google\\Chrome\\User Data\\Default\\Login Data" wide //weight: 2
        $x_2_3 = "Ave_Maria Stealer" wide //weight: 2
        $x_2_4 = "Software\\Classes\\Folder\\shell\\open\\command" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AveMaria_BF_2147837223_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AveMaria.BF!MTB"
        threat_id = "2147837223"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {a4 23 66 4c c0 62 73 0b 42 8e dc 29 2f 51 2a 5c 99 3a 4f ad 33 99 66 cf 11 b7 0c 00 aa}  //weight: 2, accuracy: High
        $x_2_2 = {2b a4 d8 52 2f 59 ca 49 9f 14 38 42 51 34 8f 7b}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AveMaria_NEDF_2147837967_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AveMaria.NEDF!MTB"
        threat_id = "2147837967"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8a 0c 06 80 e9 57 80 f1 4e 80 c1 2e 80 f1 d0 80 e9 16 80 f1 56 80 e9 66 80 f1 6e 80 e9 5b 88 0c 06 40 3b 45 f0 72 d9}  //weight: 10, accuracy: High
        $x_2_2 = "/progIDOpen" wide //weight: 2
        $x_2_3 = "/exec" wide //weight: 2
        $x_2_4 = "/realtime" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AveMaria_NEDI_2147838389_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AveMaria.NEDI!MTB"
        threat_id = "2147838389"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {83 65 0c 00 8b c6 c1 e0 04 03 45 e4 33 45 08 33 c2 2b f8 8b 45 e0 01 45 0c 29 45 fc ff 4d f4 0f 85 6e ff ff ff}  //weight: 10, accuracy: High
        $x_5_2 = {8b 01 89 45 08 8b 45 0c 01 45 08 8b 45 08 89 01 5d}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AveMaria_NEDK_2147838574_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AveMaria.NEDK!MTB"
        threat_id = "2147838574"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b c6 33 d2 f7 f7 8a 44 14 18 30 04 1e 46 81 fe 00 d0 07 00 7c c2}  //weight: 10, accuracy: High
        $x_1_2 = "topkek" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AveMaria_NEDL_2147838890_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AveMaria.NEDL!MTB"
        threat_id = "2147838890"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 45 f4 40 89 45 f4 8b 45 f4 3b 45 e0 73 25 8b 45 f4 99 6a 0c 59 f7 f9 8b 45 e4 0f b6 04 10 8b 4d dc 03 4d f4 0f b6 09 33 c8 8b 45 dc 03 45 f4 88 08 eb cc}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AveMaria_NEDO_2147838894_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AveMaria.NEDO!MTB"
        threat_id = "2147838894"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "http://ajaybnl.x10.mx" wide //weight: 5
        $x_5_2 = "detected.wav" wide //weight: 5
        $x_4_3 = "regsvr32.exe" wide //weight: 4
        $x_4_4 = "FreeAV.Scanner" wide //weight: 4
        $x_2_5 = "\\Microsoft.NET\\Framework\\v4.0.30319\\RegSvcs.exe" wide //weight: 2
        $x_2_6 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AveMaria_NEDR_2147839079_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AveMaria.NEDR!MTB"
        threat_id = "2147839079"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {0f b6 0c 10 8b 55 f8 03 55 fc 0f b6 02 33 c1 8b 4d f8 03 4d fc 88 01 eb c8}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AveMaria_AH_2147840503_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AveMaria.AH!MTB"
        threat_id = "2147840503"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {f7 bd 64 ff ff ff 89 95 58 ff ff ff 81 bd 5c ff ff ff 00 00 00 01 74 2a 8b 95 7c ff ff ff 03 95 5c ff ff ff 0f be 02 8b 8d 58 ff ff ff 0f be 54 0d 84 33 c2 8b 8d 7c ff ff ff 03 8d 5c ff ff ff 88 01 eb}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AveMaria_AH_2147840503_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AveMaria.AH!MTB"
        threat_id = "2147840503"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "FlowerPower" ascii //weight: 3
        $x_3_2 = "CreateToolhelp32Snapshot" ascii //weight: 3
        $x_3_3 = "SHGetSpecialFolderPathA" ascii //weight: 3
        $x_3_4 = "GetTokenInformation" ascii //weight: 3
        $x_3_5 = "IsWow64Process" ascii //weight: 3
        $x_3_6 = "apEqualSid" ascii //weight: 3
        $x_3_7 = "ExtTextOutA" ascii //weight: 3
        $x_3_8 = "ClientToScreen" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AveMaria_NEEF_2147840887_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AveMaria.NEEF!MTB"
        threat_id = "2147840887"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 95 7c ff ff ff 03 95 5c ff ff ff 0f be 02 8b 8d 58 ff ff ff 0f be 54 0d 84 33 c2 8b 8d 7c ff ff ff 03 8d 5c ff ff ff 88 01 eb 98}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AveMaria_NEEG_2147840978_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AveMaria.NEEG!MTB"
        threat_id = "2147840978"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {89 44 24 10 8b 44 24 28 31 44 24 14 8b 4c 24 10 31 4c 24 14 8b 44 24 18 89 44 24 2c 8b 44 24 14 29 44 24 2c 8b 44 24 2c 89 44 24 18 8d 44 24 30}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AveMaria_NEEL_2147841429_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AveMaria.NEEL!MTB"
        threat_id = "2147841429"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {0f be 44 15 84 33 c8 8b 95 7c ff ff ff 03 95 50 ff ff ff 88 0a eb 98}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AveMaria_RDA_2147841609_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AveMaria.RDA!MTB"
        threat_id = "2147841609"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 45 c8 83 c0 3e 89 45 a4 0f be 45 cf 0f b7 c8 0f b7 05 ?? ?? ?? ?? 66 3b c8 8a 45 cf 0f 94 c2 33 c9 3c 48 0f 94 c1 3b d1}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AveMaria_NEEQ_2147841613_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AveMaria.NEEQ!MTB"
        threat_id = "2147841613"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 f0 f7 e1 d1 ea 83 e2 fc 8d 04 52 f7 d8 8a 84 06 5b 2a ?? 00 30 04 33 46 39 f7 75 e3}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AveMaria_GFE_2147841688_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AveMaria.GFE!MTB"
        threat_id = "2147841688"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b c6 33 d2 f7 f3 8a 44 14 18 30 04 2e 46 81 fe ?? ?? ?? ?? 7c}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AveMaria_NEET_2147842214_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AveMaria.NEET!MTB"
        threat_id = "2147842214"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {f7 f9 8b 45 e8 0f b6 0c 10 8b 55 f4 03 55 fc 0f b6 02 33 c1 8b 4d f4 03 4d fc 88 01 8b 55 fc 83 c2 01 89 55 fc eb c8}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AveMaria_RPZ_2147843253_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AveMaria.RPZ!MTB"
        threat_id = "2147843253"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 5d 90 33 c9 bf 64 00 00 00 0f 1f 00 8b c1 33 d2 f7 f7 8a 44 15 98 30 04 19 41 81 f9 00 78 05 00 7c ea 6a 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AveMaria_RB_2147845820_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AveMaria.RB!MTB"
        threat_id = "2147845820"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 80 03 45 90 0f be 08 8b 95 60 ff ff ff 0f be 44 15 98 33 c8 8b 55 80 03 55 90 88 0a eb b3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AveMaria_GHW_2147845823_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AveMaria.GHW!MTB"
        threat_id = "2147845823"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b c6 33 d2 f7 f7 8a 84 14 ?? ?? ?? ?? 30 04 1e 46 81 fe ?? ?? ?? ?? 7c}  //weight: 10, accuracy: Low
        $x_10_2 = {56 57 6a 40 68 00 30 00 00 68 00 00 a0 00 6a 00 ff 15}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AveMaria_GHG_2147847790_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AveMaria.GHG!MTB"
        threat_id = "2147847790"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b c1 6a 64 99 5f f7 ff 8a 44 15 98 30 04 31 41 81 f9 00 78 05 00 7c e0}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AveMaria_GJR_2147848648_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AveMaria.GJR!MTB"
        threat_id = "2147848648"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 4d ff 03 c1 0f bf 55 e4 2b c2 0f b6 4d fb 0f be 55 fd 33 ca 0f af c1 88 45 ef b8 ?? ?? ?? ?? 69 c8 f3 00 00 00 8a 15 ?? ?? ?? ?? 88 91 ?? ?? ?? ?? 0f b6 05 ?? ?? ?? ?? 83 c0 11 a2 ?? ?? ?? ?? 8b 4d cc 83 c1 01 89 4d cc 81 7d ?? ?? ?? ?? ?? 0f 8c}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AveMaria_BM_2147849348_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AveMaria.BM!MTB"
        threat_id = "2147849348"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {8a 04 0f c0 c8 03 32 83 [0-4] 6a 0c 88 04 0f 8d 43 01 99 5e f7 fe 41 8b da 81 f9 [0-4] 7c}  //weight: 4, accuracy: Low
        $x_1_2 = {6a 40 68 00 10 00 00 68 ?? ?? 00 00 57 8b f0 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AveMaria_BN_2147849349_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AveMaria.BN!MTB"
        threat_id = "2147849349"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {c1 e2 05 0b ca 0f b6 85 [0-4] 33 c8 8b 55 dc 03 55 f8 88 0a 8b 45 e8 83 c0 01 99 b9 0c 00 00 00 f7 f9 89 55 e8 eb}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AveMaria_NA_2147910570_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AveMaria.NA!MTB"
        threat_id = "2147910570"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MALINAGERBITALASOMEDAKONIRAMICRAPC" ascii //weight: 1
        $x_1_2 = "AMPOSCOLA" ascii //weight: 1
        $x_1_3 = "CEDREKASMPS" ascii //weight: 1
        $x_1_4 = "THEBSFOUR" ascii //weight: 1
        $x_1_5 = "WECHANGEMOSAWASDMM" ascii //weight: 1
        $x_1_6 = "IENUSONE" ascii //weight: 1
        $x_1_7 = "UTMAGOSIT" ascii //weight: 1
        $x_1_8 = "yTHECO" ascii //weight: 1
        $x_1_9 = "XHSHOTPS" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

