rule Trojan_Win32_Stealz_ZAT_2147943075_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealz.ZAT!MTB"
        threat_id = "2147943075"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "do curl -X POST" wide //weight: 1
        $x_1_2 = "bitcoin" wide //weight: 1
        $x_1_3 = "credential" wide //weight: 1
        $x_1_4 = "backup" wide //weight: 1
        $x_1_5 = "screenshot" wide //weight: 1
        $x_1_6 = "recovery" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealz_ZCT_2147943076_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealz.ZCT!MTB"
        threat_id = "2147943076"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Add-Type -AssemblyName System.Security" wide //weight: 1
        $x_1_2 = "::Unprotect([System.Convert]::FromBase64String(" wide //weight: 1
        $x_1_3 = "[System.Security.Cryptography.DataProtectionScope]::CurrentUser)" wide //weight: 1
        $x_1_4 = "$null" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealz_CA_2147968451_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealz.CA!MTB"
        threat_id = "2147968451"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {66 0f 7e c0 66 0f 6e 44 0c ?? 66 0f 6e c8 0f 57 c8 66 0f 7e 89}  //weight: 10, accuracy: Low
        $x_10_2 = {8a c1 c0 e0 05 2a c1 04 07 02 c2 32 44 0c ?? 88 81}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

