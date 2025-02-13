rule Trojan_Win64_Expiro_AA_2147793770_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Expiro.AA!MTB"
        threat_id = "2147793770"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Expiro"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "SplashWindow" ascii //weight: 3
        $x_3_2 = "e&JHZ<lwVoNWj" ascii //weight: 3
        $x_3_3 = "TO|Djiu" ascii //weight: 3
        $x_3_4 = "ShapeCollector.pdb" ascii //weight: 3
        $x_3_5 = "CommandLineToArgvW" ascii //weight: 3
        $x_3_6 = "ShellExecuteExW" ascii //weight: 3
        $x_3_7 = "EtwLogTraceEvent" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Expiro_RPX_2147907534_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Expiro.RPX!MTB"
        threat_id = "2147907534"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Expiro"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 91 cc 00 00 00 f7 91 34 01 00 00 48 81 c6 00 04 00 00 48 81 c1 00 04 00 00 48 81 fe 00 c0 08 00 0f 85 ?? ?? ff ff 59 e8 ?? ?? ff ff 48 8b e5 5d 41 5f 41 5e 41 5d 41 5c 41 5b 41 5a 41 59 41 58 5f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

