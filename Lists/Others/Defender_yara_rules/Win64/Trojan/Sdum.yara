rule Trojan_Win64_Sdum_HNS_2147904988_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Sdum.HNS!MTB"
        threat_id = "2147904988"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Sdum"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {c7 85 b0 05 00 00 a2 01 00 00 48 89 9d b8 05 00 00 48 89 9d c8 05 00 00 48 89 9d d0 05 00 00 48 89 9d c8 05 00 00 48 c7 85 d0 05 00 00 0f 00 00 00 88 9d b8 05 00 00 44 8d 43 0c}  //weight: 2, accuracy: High
        $x_2_2 = {c7 45 98 65 00 00 00 48 89 5d a0 0f 57 c0 66 0f 7f 45 b0}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Sdum_RL_2147907833_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Sdum.RL!MTB"
        threat_id = "2147907833"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Sdum"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "infinitycheats\\GameHelpersLoader__APEX_NEW\\GameHelpersLoader__APEX_NEW\\bin\\x64\\Release\\net8.0-windows\\win-x64\\native\\APEX_NEW_LOADER.pdb" ascii //weight: 5
        $x_5_2 = "infinitycheats\\GameHelpersLoader__APEX_NEW\\GameHelpersLoader__APEX_NEW\\bin\\x64\\Release\\net8.0-windows\\win-x64\\native\\ApexLoader.pdb" ascii //weight: 5
        $x_1_3 = {34 3b 32 71 70 5a 5c 22 70 5a 5c 22 70 5a 5c 22 81 d8 5f 23 79 5a 5c 22 81 d8 58 23 7c 5a 5c 22}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_Sdum_RM_2147908196_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Sdum.RM!MTB"
        threat_id = "2147908196"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Sdum"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "infinitycheats\\GameHelpersLoader__APEX_TMH\\GameHelpersLoader__APEX_TMH\\bin\\Release\\net8.0-windows\\win-x64\\native\\APEX_TMH_LOADER.pdb" ascii //weight: 5
        $x_5_2 = "infinitycheats\\GameHelpersLoader__APEX_TMH\\GameHelpersLoader__APEX_TMH\\bin\\Release\\net8.0-windows\\win-x64\\native\\GameHelpersLoader__APEX_TMH.pdb" ascii //weight: 5
        $x_1_3 = {34 bb 32 71 70 da 5c 22 70 da 5c 22 70 da 5c 22}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_Sdum_NRAA_2147911456_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Sdum.NRAA!MTB"
        threat_id = "2147911456"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Sdum"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "infinitycheats\\GameHelpersLoader__APEX_NEW\\GameHelpersLoader__APEX_NEW\\bin\\x64\\Release\\net8.0-windows\\win-x64\\native\\ApexLoader.pdb" ascii //weight: 4
        $x_1_2 = {28 c0 f1 71 6c a1 9f 22 6c a1 9f 22 6c a1 9f 22}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Sdum_RV_2147911598_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Sdum.RV!MTB"
        threat_id = "2147911598"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Sdum"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {48 8b 44 24 28 48 8b 4c 24 08 0f b7 04 48 89 04 24 33 d2 48 8b 44 24 08 b9 05 00 00 00 48 f7 f1 48 8b c2 48 8d 0d f7 87 03 00 0f b7 04 41 8b 0c 24 33 c8 8b c1 48 8b 4c 24 20 48 8b 54 24 08 66 89 04 51 eb a2}  //weight: 5, accuracy: High
        $x_1_2 = "Instant Verification Tool" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Sdum_CF_2147955236_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Sdum.CF!MTB"
        threat_id = "2147955236"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Sdum"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "APEX_TMH_LOADER.pdb" ascii //weight: 2
        $x_2_2 = ".managedcode" ascii //weight: 2
        $x_2_3 = "hydrated" ascii //weight: 2
        $x_2_4 = "PEX_TMH_LOADER.exe" ascii //weight: 2
        $x_2_5 = "DOTNET_" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Sdum_AHC_2147961568_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Sdum.AHC!MTB"
        threat_id = "2147961568"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Sdum"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "100"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Windows Component Update Service" ascii //weight: 10
        $x_20_2 = "Windows Software Foundation" ascii //weight: 20
        $x_30_3 = "powershell -WindowStyle Hidden -Command \"$WS = New-Object -ComObject WScript.Shell; $SC = $WS.CreateShortcut(" ascii //weight: 30
        $x_40_4 = "MicrosoftEdgeUpdate.lnk" ascii //weight: 40
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

