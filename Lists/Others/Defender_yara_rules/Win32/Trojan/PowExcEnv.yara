rule Trojan_Win32_PowExcEnv_B_2147936897_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PowExcEnv.B!MTB"
        threat_id = "2147936897"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PowExcEnv"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Set-MpPreference" wide //weight: 10
        $x_1_2 = "-DisableIntrusionPreventionSystem $true" wide //weight: 1
        $x_1_3 = "-DisableIOAVProtection $true" wide //weight: 1
        $x_1_4 = "-DisableRealtimeMonitoring $true" wide //weight: 1
        $x_1_5 = "-DisableScriptScanning $true" wide //weight: 1
        $x_1_6 = "-EnableControlledFolderAccess Disabled" wide //weight: 1
        $x_1_7 = "-SubmitSamplesConsent NeverSend" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_PowExcEnv_ZA_2147943072_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PowExcEnv.ZA!MTB"
        threat_id = "2147943072"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PowExcEnv"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "add-mppreference -exclusionpath $" wide //weight: 1
        $x_1_2 = "add-mppreference -exclusionprocess $" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_PowExcEnv_ZB_2147943074_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PowExcEnv.ZB!MTB"
        threat_id = "2147943074"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PowExcEnv"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "add-mppreference -exclusionpath $" wide //weight: 1
        $x_1_2 = "add-mppreference -exclusionprocess $" wide //weight: 1
        $x_1_3 = "foreach ($" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PowExcEnv_H_2147946382_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PowExcEnv.H!MTB"
        threat_id = "2147946382"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PowExcEnv"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Add-MpPreference" wide //weight: 1
        $x_1_2 = "-exclusion" wide //weight: 1
        $x_1_3 = "$env:" wide //weight: 1
        $x_1_4 = "appdata" wide //weight: 1
        $x_1_5 = "-replace" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PowExcEnv_PA_2147948645_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PowExcEnv.PA!MTB"
        threat_id = "2147948645"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PowExcEnv"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Add-MpPreference" wide //weight: 2
        $x_1_2 = "-ExclusionProcess" wide //weight: 1
        $x_1_3 = "Get-Process -PID" wide //weight: 1
        $x_1_4 = "MainModule.ModuleName" wide //weight: 1
        $x_1_5 = "-Force" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PowExcEnv_PB_2147948646_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PowExcEnv.PB!MTB"
        threat_id = "2147948646"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PowExcEnv"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Add-MpPreference" wide //weight: 2
        $x_1_2 = "-ExclusionPath" wide //weight: 1
        $x_1_3 = "(Get-Location)" wide //weight: 1
        $x_1_4 = "-Force" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PowExcEnv_RXH_2147948914_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PowExcEnv.RXH!MTB"
        threat_id = "2147948914"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PowExcEnv"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {61 00 64 00 64 00 2d 00 6d 00 70 00 70 00 72 00 65 00 66 00 65 00 72 00 65 00 6e 00 63 00 65 00 20 00 2d 00 65 00 78 00 63 00 6c 00 75 00 73 00 69 00 6f 00 6e 00 70 00 61 00 74 00 68 00 [0-255] 61 00 64 00 64 00 2d 00 6d 00 70 00 70 00 72 00 65 00 66 00 65 00 72 00 65 00 6e 00 63 00 65 00 20 00 2d 00 65 00 78 00 63 00 6c 00 75 00 73 00 69 00 6f 00 6e 00 70 00 72 00 6f 00 63 00 65 00 73 00 73 00}  //weight: 5, accuracy: Low
        $x_5_2 = {61 00 64 00 64 00 2d 00 6d 00 70 00 70 00 72 00 65 00 66 00 65 00 72 00 65 00 6e 00 63 00 65 00 20 00 2d 00 65 00 78 00 63 00 6c 00 75 00 73 00 69 00 6f 00 6e 00 70 00 72 00 6f 00 63 00 65 00 73 00 73 00 [0-255] 61 00 64 00 64 00 2d 00 6d 00 70 00 70 00 72 00 65 00 66 00 65 00 72 00 65 00 6e 00 63 00 65 00 20 00 2d 00 65 00 78 00 63 00 6c 00 75 00 73 00 69 00 6f 00 6e 00 70 00 61 00 74 00 68 00}  //weight: 5, accuracy: Low
        $x_1_3 = "\\appdata\\" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_PowExcEnv_G_2147957029_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PowExcEnv.G!MTB"
        threat_id = "2147957029"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PowExcEnv"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Powershell" wide //weight: 1
        $x_1_2 = "add-mppreference" wide //weight: 1
        $x_1_3 = "-exclusionpath" wide //weight: 1
        $x_1_4 = "$env:USERPROFILE" wide //weight: 1
        $x_1_5 = "appdata" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PowExcEnv_RHA_2147957177_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PowExcEnv.RHA!MTB"
        threat_id = "2147957177"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PowExcEnv"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "31"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 [0-112] 24 00}  //weight: 10, accuracy: Low
        $x_10_2 = "::Frombase64string($" wide //weight: 10
        $x_10_3 = ".replace(''" wide //weight: 10
        $x_1_4 = ");iex $" wide //weight: 1
        $x_1_5 = ");invoke-expression $" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

