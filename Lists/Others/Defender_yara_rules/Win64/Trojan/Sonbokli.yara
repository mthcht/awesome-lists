rule Trojan_Win64_Sonbokli_GVA_2147936088_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Sonbokli.GVA!MTB"
        threat_id = "2147936088"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Sonbokli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 89 c2 48 8b 45 18 48 01 d0 0f b6 08 48 8b 55 10 48 8b 45 f8 48 01 d0 44 89 c2 31 ca 88 10 48 83 45 f8 01 48 8b 45 f8 48 3b 45 20 72 bc}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Sonbokli_GVB_2147936089_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Sonbokli.GVB!MTB"
        threat_id = "2147936089"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Sonbokli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 01 d0 44 0f b6 00 48 8b 45 f8 83 e0 0f 48 89 c2 48 8b 45 18 48 01 d0 0f b6 08 48 8b 55 10 48 8b 45 f8 48 01 d0 44 89 c2 31 ca 88 10 48 83 45 f8 01 48 8b 45 f8 48 3b 45 20}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Sonbokli_AN_2147981762_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Sonbokli.AN!MTB"
        threat_id = "2147981762"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Sonbokli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_2 = "PayloadKeepAlive skipped: server URL is empty" ascii //weight: 1
        $x_1_3 = "SELECT * FROM Win32_ProcessStartTrace WHERE ProcessName='explorer.exe'" ascii //weight: 1
        $x_1_4 = "bld_WrhPmSV4V4TJSTXsDdtCrIh2.exe" ascii //weight: 1
        $x_2_5 = {68 74 74 70 3a 2f 2f 32 31 36 2e 31 35 38 2e 39 35 2e 31 38 33 3a 38 30 39 33 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Sonbokli_BN_2147981892_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Sonbokli.BN!MTB"
        threat_id = "2147981892"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Sonbokli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_2 = "PayloadKeepAlive skipped: server URL is empty" ascii //weight: 1
        $x_1_3 = "SELECT * FROM Win32_ProcessStartTrace WHERE ProcessName='explorer.exe'" ascii //weight: 1
        $x_1_4 = "Microsoft\\Terminal Server Client\\state.bin" ascii //weight: 1
        $x_1_5 = "Microsoft\\OneDriveStandalone\\cache.dat" ascii //weight: 1
        $x_2_6 = {68 74 74 70 3a 2f 2f 32 31 36 2e 31 35 38 2e 39 35 2e 31 38 33 3a 38 30 39 33 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Sonbokli_DN_2147981893_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Sonbokli.DN!MTB"
        threat_id = "2147981893"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Sonbokli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "SELECT * FROM __FilterToConsumerBinding WHERE Filter LIKE" ascii //weight: 1
        $x_1_2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_3 = "PayloadKeepAlive skipped: server URL is empty" ascii //weight: 1
        $x_1_4 = "SELECT * FROM Win32_ProcessStartTrace WHERE ProcessName='explorer.exe'" ascii //weight: 1
        $x_1_5 = "Microsoft\\Terminal Server Client\\state.bin" ascii //weight: 1
        $x_1_6 = "Microsoft\\OneDriveStandalone\\cache.dat" ascii //weight: 1
        $x_2_7 = {4c 4f 4c 44 5f 43 46 47 5f 56 31 00 00 00 00 00 68 74 74 70 3a 2f 2f [0-21] 38 30 39 33 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

