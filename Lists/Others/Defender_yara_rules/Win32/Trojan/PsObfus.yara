rule Trojan_Win32_PsObfus_Z_2147959525_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PsObfus.Z!MTB"
        threat_id = "2147959525"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PsObfus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell" wide //weight: 1
        $x_1_2 = "] $_-As[cHar]" wide //weight: 1
        $x_1_3 = "join" wide //weight: 1
        $x_1_4 = "foreach-object" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

