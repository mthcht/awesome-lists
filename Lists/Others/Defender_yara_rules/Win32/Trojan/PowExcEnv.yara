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

