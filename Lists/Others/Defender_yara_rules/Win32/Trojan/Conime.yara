rule Trojan_Win32_Conime_A_2147683063_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Conime.A"
        threat_id = "2147683063"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Conime"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {c7 45 d4 04 00 02 80 52 c7 45 cc 0a 00 00 00 ff 15 ?? ?? ?? ?? d9 5d 88 d9 45 88 d8 0d ?? ?? ?? ?? 8b 45 dc c7 45 8c 08 00 00 00 89 45 94 df e0 a8 0d}  //weight: 2, accuracy: Low
        $x_1_2 = "[-] ERROR: op/ logf" ascii //weight: 1
        $x_1_3 = "conime" wide //weight: 1
        $x_1_4 = "net stop alg" wide //weight: 1
        $x_1_5 = "netsh firewall set opmode disable" wide //weight: 1
        $x_1_6 = "?ac=get&u=" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Conime_B_2147683066_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Conime.B"
        threat_id = "2147683066"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Conime"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 45 fc 05 00 00 00 8b 45 08 0f bf 00 85 c0 74 ?? c7 45 fc 06 00 00 00 8b 55 d0 8d 4d cc e8 ?? ?? ?? ?? 8d 45 cc 89 45 a0 c7 45 98 08 40 00 00 0f bf 45 dc}  //weight: 1, accuracy: Low
        $x_1_2 = "net stop alg" wide //weight: 1
        $x_1_3 = "netsh firewall set opmode disable" wide //weight: 1
        $x_1_4 = "select=phone&DnaMobileCode=" wide //weight: 1
        $x_1_5 = "select=card&pwdHex=" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

