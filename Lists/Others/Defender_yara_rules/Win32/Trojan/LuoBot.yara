rule Trojan_Win32_LuoBot_RPY_2147816703_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LuoBot.RPY!MTB"
        threat_id = "2147816703"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LuoBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 f7 89 f0 31 db 81 c7 ?? ?? 00 00 81 2e ?? ?? ?? ?? 83 c6 04 39 fe 7c f3}  //weight: 1, accuracy: Low
        $x_1_2 = {89 f7 31 c0 40 89 f0 81 c7 ?? ?? 00 00 81 2e ?? ?? ?? ?? 83 c6 04 39 fe 7c f3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_LuoBot_RPZ_2147816704_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LuoBot.RPZ!MTB"
        threat_id = "2147816704"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LuoBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 f7 89 f0 31 db 81 c7 ?? ?? 00 00 81 2e ?? ?? ?? ?? 83 c6 04 66 ba 80 9a 39 fe 7c ef}  //weight: 1, accuracy: Low
        $x_1_2 = {89 f7 31 c0 89 f0 81 c7 ?? ?? 00 00 81 2e ?? ?? ?? ?? 83 c6 04 39 fe 7c f3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

