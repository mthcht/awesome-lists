rule Trojan_Win32_Phoenix_RPY_2147850595_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Phoenix.RPY!MTB"
        threat_id = "2147850595"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Phoenix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6a 40 68 00 30 00 00 ff 76 50 33 c0 50 ff 95 74 ff ff ff 8b f8 85 ff 0f 84 58 02 00 00 6a 40 68 00 30 00 00 ff 76 50 ff 76 34 ff 75 e4 ff 55 dc 89 45 fc 85 c0 75 41 85 db 75 18 ff 76 34 ff 75 e4 ff 55 b8 6a 40 68 00 30 00 00 ff 76 50 ff 76 34}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

