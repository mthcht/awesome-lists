rule Trojan_Win32_ShellcodeInject_ZX_2147914001_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ShellcodeInject.ZX!MTB"
        threat_id = "2147914001"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ShellcodeInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {80 34 18 2d 40 3b c7 72 f7 60 ff 95 8c fd ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ShellcodeInject_AMZ_2147922792_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ShellcodeInject.AMZ!MTB"
        threat_id = "2147922792"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ShellcodeInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {31 d2 f7 74 24 2c 8b 44 24 18 0f be 0c 11 31 c8 88 c2 8b 84 24 44 01 00 00 8b 4c 24 28 88 14 08 8b 44 24 28 83 c0 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

