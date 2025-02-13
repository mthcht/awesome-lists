rule Trojan_Win32_Turkojan_A_2147610966_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Turkojan.A!dll"
        threat_id = "2147610966"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Turkojan"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4b 42 48 6f 6f 6b 2e 64 6c 6c 00 43 72 65 61 74 65 48 6f 6f 6b 00 44 65 6c 65 74 65 48 6f 6f 6b 00}  //weight: 1, accuracy: High
        $x_1_2 = "TheCanMeButThe" ascii //weight: 1
        $x_3_3 = {f7 c7 00 00 00 80 75 33 83 c3 f0 83 eb 03 0f 92 c0 34 01 0a 05 ?? ?? 40 00 74 20 e8 ?? ?? ff ff 50 0f b7 05 ?? ?? 40 00 50 68 2c cf 00 00}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Turkojan_B_2147610967_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Turkojan.B!dll"
        threat_id = "2147610967"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Turkojan"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {77 73 6f 63 6b 33 32 5f 68 6f 6f 6b 2e 64 6c 6c 00 44 4c 4c 49 6e 6a 65 63 74 65 64 41 64 64 00 44 4c 4c 52 65 6d 6f 76 65 00}  //weight: 1, accuracy: High
        $x_1_2 = {44 4c 4d 4e 49 55 6d 73 6e 00 00 00 09 6d 73 74 77 61 69 6e 33 32 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

