rule Trojan_Win32_Kryplod_A_2147783207_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kryplod.A!MTB"
        threat_id = "2147783207"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kryplod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 68 65 6c c7 45 ?? 6c 45 78 65 c7 45 ?? 63 75 74 65 c7 45 ?? 45 78 57 00 c7 45 ?? 53 48 45 4c c7 45 ?? 4c 33 32 00 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {2b c7 d1 f8 8d 34 46 8d 76 02 8d 3c 1e 8b cf 8d 41 02 89 85 9c fd ff ff}  //weight: 1, accuracy: High
        $x_1_3 = {2b f9 be 00 00 00 00 d1 ff b9 fe ff ff ff 8d 04 3f 2b c8 01 8d a8 fd ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

