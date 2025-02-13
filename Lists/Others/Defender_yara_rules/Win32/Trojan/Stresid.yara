rule Trojan_Win32_Stresid_E_2147597692_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stresid.gen!E"
        threat_id = "2147597692"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stresid"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 07 57 ba ?? ?? ?? 00 e8 ?? ?? 00 00 50 8d 4d 10 e8 ?? ?? ff ff 3b c7 0f 8c ?? ?? 00 00 66 83 4d 9c ff 66 c7 45 94 0b 00 51}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stresid_F_2147622803_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stresid.gen!F"
        threat_id = "2147622803"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stresid"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 07 57 ba ?? ?? ?? 00 e8 ?? ?? 00 00 50 8d 4d c8 e8 ?? ?? 00 00 3b c7 0f 8c ?? ?? 00 00 66 83 8d 28 ff ff ff ff 66 c7 85 20 ff ff ff 0b 00 51}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stresid_C_2147625842_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stresid.C"
        threat_id = "2147625842"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stresid"
        severity = "Low"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {88 84 28 f4 fe ff ff}  //weight: 1, accuracy: High
        $x_1_2 = {8a 9c 29 f4 fe ff ff}  //weight: 1, accuracy: High
        $x_1_3 = {8a 94 28 f4 fe ff ff}  //weight: 1, accuracy: High
        $x_1_4 = {8d 8c 29 f4 fe ff ff}  //weight: 1, accuracy: High
        $x_1_5 = {02 08 0f b6 c1}  //weight: 1, accuracy: High
        $x_1_6 = {8a 84 28 f4 fe ff ff 32 04 3e 88 06}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

