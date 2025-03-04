rule Trojan_Win32_ArkeiStealer_SBR_2147764235_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ArkeiStealer.SBR!MSR"
        threat_id = "2147764235"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ArkeiStealer"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "L3NlcnZlci9nYXRl" ascii //weight: 1
        $x_1_2 = "AppData\\Roaming\\Arkei" ascii //weight: 1
        $x_1_3 = "Windows_Antimalware_Host_System_Worker" ascii //weight: 1
        $x_1_4 = "Bitcoin\\wallet.dat" ascii //weight: 1
        $x_1_5 = "SELECT encryptedUsername, encryptedPassword, formSubmitURL FROM moz_logins" ascii //weight: 1
        $x_1_6 = "SELECT name_on_card, expiration_month, expiration_year, card_number_encrypted FROM credit_cards" ascii //weight: 1
        $x_1_7 = "Mozilla\\Firefox\\Profiles" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ArkeiStealer_RM_2147777559_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ArkeiStealer.RM!MTB"
        threat_id = "2147777559"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ArkeiStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 e9 4c a6 b5 f2 e8 ?? ?? ?? ?? 43 bb 44 c5 9a c3 31 32 89 c9 42 01 cb bb 26 05 bb 1f 39 fa 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ArkeiStealer_RM_2147777559_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ArkeiStealer.RM!MTB"
        threat_id = "2147777559"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ArkeiStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 14 8d 3c 03 e8 ?? ?? ?? ?? 30 07 83 fd 19 75 [0-20] ff 15 ?? ?? ?? ?? ff 74 24 ?? 56 56 ff 15 ?? ?? ?? ?? 43 3b dd 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ArkeiStealer_RM_2147777559_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ArkeiStealer.RM!MTB"
        threat_id = "2147777559"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ArkeiStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b f2 33 ed 8b d9 57 8b fd 85 f6 7e ?? 81 fe 85 02 00 00 75 ?? 55 55 55 55 55 55 ff 15 ?? ?? ?? ?? e8 ?? ?? ?? ?? 30 04 1f 47 3b fe 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ArkeiStealer_RM_2147777559_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ArkeiStealer.RM!MTB"
        threat_id = "2147777559"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ArkeiStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 ff 3b d8 7e ?? 56 eb ?? 33 c0 81 fb 85 02 00 00 75 ?? 50 50 50 50 50 50 ff 15 ?? ?? ?? ?? 8b 44 24 ?? 8d 34 07 e8 ?? ?? ?? ?? 30 06 47 3b fb 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ArkeiStealer_RM_2147777559_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ArkeiStealer.RM!MTB"
        threat_id = "2147777559"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ArkeiStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c4 89 84 24 ?? ?? ?? ?? 56 33 f6 85 ff 7e ?? 55 8b 2d ?? ?? ?? ?? 83 ff ?? 75 ?? 6a 00 6a 00 ff 15 ?? ?? ?? ?? 6a 00 ff 15 ?? ?? ?? ?? e8 ?? ?? ?? ?? 30 04 33 81 ff 91 05 00 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ArkeiStealer_RMA_2147780086_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ArkeiStealer.RMA!MTB"
        threat_id = "2147780086"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ArkeiStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c4 89 84 24 ?? ?? ?? ?? 55 8b ac 24 ?? ?? ?? ?? 56 57 33 f6 33 ff 3b de 7e ?? 81 fb 85 02 00 00 75 [0-8] ff 15 [0-16] e8 ?? ?? ?? ?? 30 04 2f 83 fb 19 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ArkeiStealer_RMA_2147780086_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ArkeiStealer.RMA!MTB"
        threat_id = "2147780086"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ArkeiStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 f6 85 ff 7e ?? 55 8b 2d ?? ?? ?? ?? 8b ff 83 ff 2d 75 ?? 6a 00 6a 00 6a 00 6a 00 6a 00 ff d5 6a 00 6a 00 6a 00 6a 00 ff 15 ?? ?? ?? ?? e8 ?? ?? ?? ?? 30 04 1e 81 ff 91 05 00 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ArkeiStealer_RT_2147780538_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ArkeiStealer.RT!MTB"
        threat_id = "2147780538"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ArkeiStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 ff 85 db 7e ?? 56 8b 44 24 ?? 8d 34 07 e8 ?? ?? ?? ?? 30 06 83 fb 19 75 ?? 6a 00 6a 00 6a 00 6a 00 ff 15 ?? ?? ?? ?? 47 3b fb 7c ?? 5e 5f 81 fb 71 11 00 00 75}  //weight: 1, accuracy: Low
        $x_1_2 = {83 ff 2d 75 ?? 6a 00 6a 00 6a 00 6a 00 6a 00 ff d5 6a 00 ff 15 ?? ?? ?? ?? e8 ?? ?? ?? ?? 30 04 1e 81 ff 91 05 00 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_ArkeiStealer_DB_2147786456_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ArkeiStealer.DB!MTB"
        threat_id = "2147786456"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ArkeiStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "125478824515ADNxu2ccbwe" ascii //weight: 3
        $x_3_2 = "msg=No-Exes-Found-To-Run" ascii //weight: 3
        $x_3_3 = "&ip=&oid=139" ascii //weight: 3
        $x_3_4 = "/dev/random" ascii //weight: 3
        $x_3_5 = "pthread_mutex_unlock" ascii //weight: 3
        $x_3_6 = "pthread_cond_broadcast" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ArkeiStealer_DK_2147787115_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ArkeiStealer.DK!MTB"
        threat_id = "2147787115"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ArkeiStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "key=125478824515ADNxu2ccbwe" ascii //weight: 3
        $x_3_2 = "msg=No-Exes-Found-To-Run" ascii //weight: 3
        $x_3_3 = "bryexhsg.xyz" ascii //weight: 3
        $x_3_4 = "&ip=&oid=3" ascii //weight: 3
        $x_3_5 = "addInstall.php?" ascii //weight: 3
        $x_3_6 = "/dev/random" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ArkeiStealer_MG_2147795837_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ArkeiStealer.MG!MTB"
        threat_id = "2147795837"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ArkeiStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell -inputformat none -outputformat none -NonInteractive -Command Add-MpPreference -ExclusionPath" ascii //weight: 1
        $x_1_2 = "http://hsiens.xyz" ascii //weight: 1
        $x_1_3 = "addInstall.php" ascii //weight: 1
        $x_1_4 = "addInstallImpression.php" ascii //weight: 1
        $x_1_5 = "myip.php" ascii //weight: 1
        $x_1_6 = "&oname[]=lih" ascii //weight: 1
        $x_1_7 = "&oname[]=Der" ascii //weight: 1
        $x_1_8 = "&oname[]=dir" ascii //weight: 1
        $x_1_9 = "&oname[]=you" ascii //weight: 1
        $x_1_10 = "&oname[]=ult" ascii //weight: 1
        $x_1_11 = "&oname[]=GCl" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ArkeiStealer_A_2147810607_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ArkeiStealer.A"
        threat_id = "2147810607"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ArkeiStealer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "reg delete \"HKLM\\Software\\Policies\\Microsoft\\Windows Defender\" /f" ascii //weight: 1
        $x_1_2 = "Microsoft\\Windows Defender\\Real-Time Protection" ascii //weight: 1
        $x_1_3 = "Microsoft\\Windows Defender\\MpEngine\" /v \"MpEnablePus" ascii //weight: 1
        $x_1_4 = "\"cam\": true," ascii //weight: 1
        $x_1_5 = "\"files\": false," ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ArkeiStealer_EN_2147834718_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ArkeiStealer.EN!MTB"
        threat_id = "2147834718"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ArkeiStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "bkjyvwxtljwhekbjurtjlnujrtijyxnwiuebhrveqwzeqrve" ascii //weight: 1
        $x_1_2 = "Could not get a handle to ntdll.dll" ascii //weight: 1
        $x_1_3 = "NtUnmapViewOfSection" ascii //weight: 1
        $x_1_4 = "puklDEVAP9DSfvFWJSWipTSIRSDn8HfxlsEZdqCU3qVJFc13" ascii //weight: 1
        $x_1_5 = "AppPolicyGetProcessTerminationMethod" ascii //weight: 1
        $x_1_6 = "GetStartupInfoW" ascii //weight: 1
        $x_1_7 = "IsProcessorFeaturePresent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ArkeiStealer_GEZ_2147841811_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ArkeiStealer.GEZ!MTB"
        threat_id = "2147841811"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ArkeiStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2b c8 8b 84 24 ?? ?? ?? ?? 03 c1 a3 ?? ?? ?? ?? 0f be 05 ?? ?? ?? ?? 35 c0 b4 00 00 88 44 24 13 39 9c 24}  //weight: 10, accuracy: Low
        $x_10_2 = {8a 44 24 10 04 ?? 02 05 ?? ?? ?? ?? 88 44 24 10 0f b7 44 24 24 33 44 24 70 89 44 24 70 eb}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ArkeiStealer_RPX_2147902534_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ArkeiStealer.RPX!MTB"
        threat_id = "2147902534"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ArkeiStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {30 04 1e 46 3b f7 7c e8 5d 5e 83 ff 2d 75 14}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ArkeiStealer_RPZ_2147902535_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ArkeiStealer.RPZ!MTB"
        threat_id = "2147902535"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ArkeiStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 45 f8 8b 45 f8 89 85 58 ff ff ff c7 85 70 ff ff ff 6b 65 72 6e c7 85 74 ff ff ff 65 6c 33 32 c7 85 78 ff ff ff 2e 64 6c 6c 83 a5 7c ff ff ff 00 8d 85 70 ff ff ff 50 ff 55 d4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

