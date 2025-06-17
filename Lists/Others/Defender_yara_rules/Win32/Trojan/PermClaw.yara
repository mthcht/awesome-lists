rule Trojan_Win32_PermClaw_A_2147943821_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PermClaw.A"
        threat_id = "2147943821"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PermClaw"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 08 03 45 fc 0f be ?? 0f b6 ?? ?? 33 ca}  //weight: 1, accuracy: Low
        $x_1_2 = {89 51 30 b8 4d 4f 00 00 8b ?? f8 66 89 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

