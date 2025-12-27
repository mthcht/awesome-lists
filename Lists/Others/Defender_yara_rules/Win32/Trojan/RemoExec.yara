rule Trojan_Win32_RemoExec_B_2147955910_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RemoExec.B!MTB"
        threat_id = "2147955910"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RemoExec"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GetString([Convert]::FromBase64String" wide //weight: 1
        $x_1_2 = "Get-Content" wide //weight: 1
        $x_1_3 = "Select-String" wide //weight: 1
        $x_1_4 = ".Matches.Groups" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

