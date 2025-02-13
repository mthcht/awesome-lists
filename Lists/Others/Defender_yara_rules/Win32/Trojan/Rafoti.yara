rule Trojan_Win32_Rafoti_B_2147605413_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rafoti.B!dll"
        threat_id = "2147605413"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rafoti"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 7f 03 00 00 6a 00 68 ?? ?? 00 ?? ff 15 ?? ?? 00 ?? 85 c0 74 07 50 ff 15 ?? ?? 00 ?? 90 [0-3] 68 ?? ?? 00 ?? 6a 00 6a 01 68 ?? ?? 00 ?? ff 15 ?? ?? 00 ?? 85 c0}  //weight: 1, accuracy: Low
        $x_2_2 = {0f b7 45 0c 99 b9 ff 00 00 00 f7 f9 8d 45 f0 50 88 55 f0 e8 ?? ?? ?? ?? 59 90 [0-2] 5f ff 75 10 56 ff 75 08 ff 35 ?? ?? 00 ?? ff 15 ?? ?? 00 ?? 5e 5b c9 c2 0c 00}  //weight: 2, accuracy: Low
        $x_1_3 = "[%04d-%02d-%02d %02d:%02d:%02d]" ascii //weight: 1
        $x_1_4 = "SetWindowsHookExA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Rafoti_C_2147605414_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rafoti.C!dll"
        threat_id = "2147605414"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rafoti"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {74 22 c6 45 ?? 64 c6 45 ?? 6d c6 45 ?? 73 c6 45 ?? 65 c6 45 ?? 72 c6 45 ?? 76 c6 45 ?? 65 c6 45 ?? 72 eb 14 c6 45 ?? 72 c6 45 ?? 70 c6 45 ?? 63 c6 45 ?? 73 c6 45 ?? 73 33 c0}  //weight: 10, accuracy: Low
        $x_1_2 = {00 53 65 72 76 69 63 65 4d 61 69 6e 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 32 30 30 00 68 74 74 70 3a 2f 2f 25 73 3a 39 30 30 31 2f 25 64 25 73 30 30}  //weight: 1, accuracy: High
        $x_1_4 = {00 48 54 54 50 3a 2f 2f 25 73 3a 25 64 2f 25 73 25 64 25 73 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

