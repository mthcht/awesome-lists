rule Trojan_Win32_SuspLoadExec_NE_2147977829_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspLoadExec.NE!MTB"
        threat_id = "2147977829"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspLoadExec"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$env:P1+$env:" wide //weight: 1
        $x_1_2 = "[Convert]::FromBase64String($" wide //weight: 1
        $x_1_3 = "[Reflection.Assembly]" wide //weight: 1
        $x_1_4 = "]::Load($" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SuspLoadExec_NF_2147978759_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspLoadExec.NF!MTB"
        threat_id = "2147978759"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspLoadExec"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$env:P1+$env:" wide //weight: 1
        $x_1_2 = "[Convert]::FromBase64String($" wide //weight: 1
        $x_1_3 = "Reflection.Assembly]" wide //weight: 1
        $x_1_4 = "::Load($" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

