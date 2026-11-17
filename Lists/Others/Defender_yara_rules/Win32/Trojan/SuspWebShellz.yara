rule Trojan_Win32_SuspWebShellz_AA_2147982229_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspWebShellz.AA!MTB"
        threat_id = "2147982229"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspWebShellz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[Convert]::ToBase64String(" wide //weight: 1
        $x_1_2 = "[IO.File]::ReadAllBytes($" wide //weight: 1
        $x_1_3 = "[IO.File]::WriteAllText" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SuspWebShellz_AB_2147982230_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspWebShellz.AB!MTB"
        threat_id = "2147982230"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspWebShellz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[convert]::tobase64string([io.file]::readallbytes(" wide //weight: 1
        $x_1_2 = ".xml" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

