rule Trojan_Win32_RevererseLoader_ZB_2147979859_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RevererseLoader.ZB!MTB"
        threat_id = "2147979859"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RevererseLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "${env:ProgramFiles" wide //weight: 1
        $x_1_2 = "]-join'') $env:" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RevererseLoader_ZE_2147980552_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RevererseLoader.ZE!MTB"
        threat_id = "2147980552"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RevererseLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$env:" wide //weight: 1
        $x_1_2 = "join" wide //weight: 1
        $x_1_3 = "&([char[]](" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RevererseLoader_ZF_2147980553_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RevererseLoader.ZF!MTB"
        threat_id = "2147980553"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RevererseLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "+$env:" wide //weight: 1
        $x_1_2 = "]::Load($" wide //weight: 1
        $x_1_3 = ":ReadAllBytes($" wide //weight: 1
        $x_1_4 = "[Convert]::FromBase64String($" wide //weight: 1
        $x_1_5 = "::WriteAllBytes($" wide //weight: 1
        $n_10_6 = "codex" wide //weight: -10
        $n_10_7 = "claude" wide //weight: -10
        $n_10_8 = "openai" wide //weight: -10
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_RevererseLoader_ZH_2147980554_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RevererseLoader.ZH!MTB"
        threat_id = "2147980554"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RevererseLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "iex (irm (" wide //weight: 1
        $x_1_2 = "' + $" wide //weight: 1
        $x_1_3 = "(Get-Random" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RevererseLoader_ZI_2147980555_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RevererseLoader.ZI!MTB"
        threat_id = "2147980555"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RevererseLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".DownloadFile($" wide //weight: 1
        $x_1_2 = "foreach ($url" wide //weight: 1
        $x_1_3 = "Net.WebClient" wide //weight: 1
        $x_1_4 = "Invoke-Item $" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

