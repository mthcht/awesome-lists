rule Trojan_Win32_SuspEncRep_Z_2147968231_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspEncRep.Z!MTB"
        threat_id = "2147968231"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspEncRep"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[system.Convert]::FromBase64String(" wide //weight: 1
        $x_1_2 = "[system.Text.Encoding]::Unicode.GetString(" wide //weight: 1
        $x_1_3 = "-replace " wide //weight: 1
        $x_1_4 = ";powershell " wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

