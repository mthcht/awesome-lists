rule Trojan_Win32_Growtopia_AMMB_2147904274_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Growtopia.AMMB!MTB"
        threat_id = "2147904274"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Growtopia"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 45 d0 c7 45 9c ?? ?? ?? ?? 89 44 24 08 c7 44 24 04 ?? ?? ?? ?? c7 04 24 ?? ?? ?? ?? e8}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Growtopia_RK_2147907700_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Growtopia.RK!MTB"
        threat_id = "2147907700"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Growtopia"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8a 85 c4 fe ff ff 30 84 0d c5 fe ff ff 41 83 f9 24 72 ed}  //weight: 5, accuracy: High
        $x_1_2 = ".growtopia2.com = %s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

