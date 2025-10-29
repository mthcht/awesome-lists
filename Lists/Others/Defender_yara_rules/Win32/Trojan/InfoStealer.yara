rule Trojan_Win32_InfoStealer_VD_2147752386_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/InfoStealer.VD!MTB"
        threat_id = "2147752386"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "InfoStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f3 0f 10 c9 f3 0f 10 f6 f3 0f 10 f6 f3 0f 10 f6 [0-21] 33 94 85 ?? ?? ?? ?? 88 16 f3 0f 10 d2 f3 0f 10 c0 f3 0f 10 c0 f3 0f 10 ff 46 [0-21] 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_InfoStealer_VD_2147752386_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/InfoStealer.VD!MTB"
        threat_id = "2147752386"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "InfoStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 74 93 10 8b 14 93 d3 c6 8b 4d 08 03 f0 c1 e9 1b d3 c2 8b 4d 08 8b c1 c1 e8 05 03 d0 8b 45 fc 33 f2 8b 55 f8 03 c2 33 f0 03 75 ec 83 6d f4 01 89 4d ec 8b cf 89 75 fc 8b fe 89 4d 08 0f 85 66 ff ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_InfoStealer_2147753775_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/InfoStealer!MTB"
        threat_id = "2147753775"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "InfoStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 34 07 0f be 1e 81 c3 ?? ?? ?? ?? e8 ?? ?? ?? ?? fe cb 32 c3 47 3b 7c 24 ?? 88 06 8b 44 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_InfoStealer_AA_2147753858_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/InfoStealer.AA!MTB"
        threat_id = "2147753858"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "InfoStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MnAuSjmDdiKM9y6Biw9KfNgUu943E5dY18" wide //weight: 1
        $x_1_2 = "FISHWORK" wide //weight: 1
        $x_1_3 = "MICROPHTHAL" wide //weight: 1
        $x_1_4 = "NONDEGENER" wide //weight: 1
        $x_1_5 = "Stjernekrigo8" wide //weight: 1
        $x_1_6 = "ESBAYDILAT" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_InfoStealer_E_2147762988_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/InfoStealer.E!MTB"
        threat_id = "2147762988"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "InfoStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "vaultcli.dll" ascii //weight: 1
        $x_3_2 = "passff.tar" ascii //weight: 3
        $x_3_3 = "cookie.tar" ascii //weight: 3
        $x_1_4 = "ie_vault" wide //weight: 1
        $x_1_5 = "LogonTrigger" wide //weight: 1
        $x_1_6 = "mail_vault" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_InfoStealer_X_2147767286_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/InfoStealer.X!MTB"
        threat_id = "2147767286"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "InfoStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://csv.posadadesantiago.com/" ascii //weight: 1
        $x_1_2 = "Content-Type: application/x-zip-compressed" ascii //weight: 1
        $x_1_3 = "http://%s/home/?id=%s&act=wbi&ver=%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_InfoStealer_VZ_2147819897_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/InfoStealer.VZ!MTB"
        threat_id = "2147819897"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "InfoStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {d4 fe ff ff 83 c0 ?? 89 85 ?? ?? ?? ?? 8b 8d ?? ?? ?? ?? 3b 4d 0c 73 22 0f b6 15 ?? ?? ?? ?? 8b 45 08 03 85 ?? ?? ?? ?? 0f b6 08 2b ca 8b 55 08 03 95 ?? ?? ?? ?? 88 0a eb c4}  //weight: 10, accuracy: Low
        $x_1_2 = "VirtualProtect" ascii //weight: 1
        $x_1_3 = ".pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_InfoStealer_VW_2147896106_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/InfoStealer.VW!MTB"
        threat_id = "2147896106"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "InfoStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {89 45 fc 8b 7d 08 33 f8 03 7d 08 33 3d 07 f8 48 00 2b 7d 10 89 7d fc 68 6b f1 48 00}  //weight: 10, accuracy: High
        $x_10_2 = {6a 01 6a 0c 6a 6f 68 1e f4 48 00 6a 55 6a 5b 68 41 f6 48 00}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_InfoStealer_RP_2147906383_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/InfoStealer.RP!MTB"
        threat_id = "2147906383"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "InfoStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "83"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "seawyrm" ascii //weight: 1
        $x_1_2 = "knight" ascii //weight: 1
        $x_1_3 = "griffin" ascii //weight: 1
        $x_1_4 = "Sea Wyrm" ascii //weight: 1
        $x_1_5 = "Knight" ascii //weight: 1
        $x_1_6 = "Griffin" ascii //weight: 1
        $x_20_7 = "SimulationEngine.Properties.Resources" ascii //weight: 20
        $x_20_8 = "castle_window" ascii //weight: 20
        $x_20_9 = "Lake_Jungle" ascii //weight: 20
        $x_20_10 = "SSUI_HelpDiagram_Animation1" ascii //weight: 20
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_20_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_InfoStealer_AMTB_2147956317_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/InfoStealer!AMTB"
        threat_id = "2147956317"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "InfoStealer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\AppData\\Local\\Temp\\Web Data" ascii //weight: 1
        $x_1_2 = "\\AppData\\Local\\Temp\\Login Data" ascii //weight: 1
        $x_1_3 = "\\logins.json" ascii //weight: 1
        $x_1_4 = "\\AppData\\Local\\Temp\\Cookies" ascii //weight: 1
        $x_1_5 = "--disable" ascii //weight: 1
        $x_2_6 = "--disable-client-side-phishing-detection" ascii //weight: 2
        $x_2_7 = "--disable-background-networking" ascii //weight: 2
        $x_2_8 = "Elevator.exe" ascii //weight: 2
        $x_2_9 = "172.67.178.5" ascii //weight: 2
        $x_2_10 = "badnesspandemic.shop" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

