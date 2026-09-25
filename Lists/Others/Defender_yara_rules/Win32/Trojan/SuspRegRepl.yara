rule Trojan_Win32_SuspRegRepl_NT_2147978862_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspRegRepl.NT!MTB"
        threat_id = "2147978862"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspRegRepl"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "::FromBase64String([regex]::Replace($" wide //weight: 1
        $x_1_2 = "[char[]]$" wide //weight: 1
        $x_1_3 = "]-bxor$" wide //weight: 1
        $x_1_4 = "[Convert]::ToInt32($" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

