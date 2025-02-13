rule Trojan_Win32_TeamBot_DA_2147908454_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TeamBot.DA!MTB"
        threat_id = "2147908454"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TeamBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 e8 c1 e8 05 89 45 f0 8b 4d fc 33 db 33 4d f4 8b 45 f0 03 c2 89 4d fc 33 c1 c7 05 ?? ?? ?? ?? ee 3d ea f4 8b 0d ?? ?? ?? ?? 89 45 f0 81 f9 13 02 00 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

