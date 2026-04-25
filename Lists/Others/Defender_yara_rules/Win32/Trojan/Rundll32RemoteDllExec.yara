rule Trojan_Win32_Rundll32RemoteDllExec_DA_2147967768_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rundll32RemoteDllExec.DA!MTB"
        threat_id = "2147967768"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rundll32RemoteDllExec"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "rundll32.exe \\\\" wide //weight: 1
        $x_1_2 = "3d80df5d12cdfe6450a782fc87bf66b444.google,#" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

