rule HackTool_Win32_SpoofPrnt_A_2147796130_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/SpoofPrnt.A!dha"
        threat_id = "2147796130"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "SpoofPrnt"
        severity = "High"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PrintSpoofer v%ws (by @itm4n)" wide //weight: 1
        $x_1_2 = "[-] A privilege is missing: '%ws'" wide //weight: 1
        $x_1_3 = "[!] CreateProcessAsUser() failed because of a missing privilege, retrying with CreateProcessWithTokenW()." wide //weight: 1
        $x_1_4 = "  - Get a SYSTEM reverse shell" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule HackTool_Win32_SpoofPrnt_SGA_2147892284_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/SpoofPrnt.SGA!MTB"
        threat_id = "2147892284"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "SpoofPrnt"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "get_download" ascii //weight: 1
        $x_1_2 = "set_UseShellExecute" ascii //weight: 1
        $x_1_3 = "regSpoof" ascii //weight: 1
        $x_1_4 = "KeyAuth" ascii //weight: 1
        $x_1_5 = "webhook" ascii //weight: 1
        $x_1_6 = "getSpoofingRegistryKeys" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

