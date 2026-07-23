rule Trojan_PowerShell_SuspAssemLoad_ZI_2147974352_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:PowerShell/SuspAssemLoad.ZI!MTB"
        threat_id = "2147974352"
        type = "Trojan"
        platform = "PowerShell: "
        family = "SuspAssemLoad"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FromBase64String($" wide //weight: 1
        $x_1_2 = "-bxor [int]$" wide //weight: 1
        $x_1_3 = "[Text.Encoding]::ASCII.GetString($" wide //weight: 1
        $x_1_4 = "$env:appdata+$" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

