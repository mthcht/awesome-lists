rule Trojan_Win64_TrueBot_RPX_2147844388_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/TrueBot.RPX!MTB"
        threat_id = "2147844388"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "TrueBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ChkdskExs" wide //weight: 1
        $x_1_2 = "ProcessHacker.exe" wide //weight: 1
        $x_1_3 = "ResourceHacker.exe" wide //weight: 1
        $x_1_4 = "process call create \"powershell -executionpolicy bypass -nop -w hidden %s" ascii //weight: 1
        $x_1_5 = "POST %s HTTP/1.0" ascii //weight: 1
        $x_1_6 = "ShellExecuteExA" ascii //weight: 1
        $x_1_7 = "wmic.exe" ascii //weight: 1
        $x_1_8 = "%s\\%08x-%08x.ps1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_TrueBot_SB_2147905992_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/TrueBot.SB!MTB"
        threat_id = "2147905992"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "TrueBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 fe c1 4c 8d 04 24 41 0f b6 c1 48 8d 0c 24 4c 03 c0 4d 8d 52 ?? 41 0f b6 10 44 02 da}  //weight: 1, accuracy: Low
        $x_1_2 = {41 0f b6 c3 48 03 c8 0f b6 01 41 88 00 88 11 41 0f b6 08 48 03 ca 0f b6 c1 0f b6 0c 04 41 30 4a ?? 48 83 eb ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

