rule Trojan_MSIL_ReverseShell_ARL_2147847781_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ReverseShell.ARL!MTB"
        threat_id = "2147847781"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ReverseShell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0d 2b 2e 06 6f ?? ?? ?? 0a 8d 19 00 00 01 13 05 07 11 05 16 11 05 8e 69 6f ?? ?? ?? 0a 26 09 28 ?? ?? ?? 0a 11 05 6f}  //weight: 2, accuracy: Low
        $x_1_2 = "RevShellAI" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ReverseShell_ZJV_2147941274_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ReverseShell.ZJV!MTB"
        threat_id = "2147941274"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ReverseShell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8e 69 0a 03 8d ?? 00 00 01 0b 16 0c 2b 17 00 07 08 02 08 91 7e ?? 00 00 04 08 06 5d 91 61 d2 9c 00 08 17 58 0c 08 03 fe 04 13 04 11 04 2d df 07 0d 2b 00 09 2a}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

