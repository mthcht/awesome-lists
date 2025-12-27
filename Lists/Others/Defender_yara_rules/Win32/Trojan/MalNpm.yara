rule Trojan_Win32_MalNpm_B_2147958794_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MalNpm.B!MTB"
        threat_id = "2147958794"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MalNpm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell" wide //weight: 1
        $x_1_2 = "webhook.site" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_MalNpm_C_2147958795_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MalNpm.C!MTB"
        threat_id = "2147958795"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MalNpm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "where bun" wide //weight: 1
        $x_1_2 = "Environment]::GetEnvironmentVariable" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

