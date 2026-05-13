rule Trojan_Win32_PsExec_DA_2147968642_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PsExec.DA!MTB"
        threat_id = "2147968642"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PsExec"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "([scriptblock]::Create($" wide //weight: 1
        $x_1_2 = "[System.IO.File]::ReadAllText" wide //weight: 1
        $x_1_3 = "-split" wide //weight: 1
        $x_1_4 = "MAS_" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PsExec_DB_2147969143_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PsExec.DB!MTB"
        threat_id = "2147969143"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PsExec"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/v:on /c" wide //weight: 1
        $x_1_2 = "=pow" wide //weight: 1
        $x_1_3 = "&&call C:\\" wide //weight: 1
        $x_1_4 = "!x!!y! -E" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

