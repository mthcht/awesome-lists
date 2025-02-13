rule Trojan_Win32_Sanpec_A_2147608367_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sanpec.gen!A"
        threat_id = "2147608367"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sanpec"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 14 01 80 f2 ?? 88 10 40 ?? 75 f4 [0-1] 68 80 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {05 78 56 34 12 83 c4 ?? ?? c9 ?? ?? ?? ?? ?? [0-1] 7e ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 8a 54 15 ?? 32 14 ?? ?? 3b [0-2] 88 10 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Sanpec_B_2147616726_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sanpec.gen!B"
        threat_id = "2147616726"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sanpec"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {b9 38 01 00 00 8a 10 80 f2 ?? 88 10 40 49 75 f5 c3}  //weight: 5, accuracy: Low
        $x_5_2 = {50 c6 44 24 ?? 4f c6 44 24 ?? 77 c6 44 24 ?? 34 c6 44 24 ?? 2e c6 44 24 ?? 63 c6 44 24 ?? 67 c6 44 24 ?? 69 c6 44 24 ?? 00}  //weight: 5, accuracy: Low
        $x_5_3 = {32 d1 88 14 30 48 75 f1 8a 16 80 f2 ?? 88 16 8a c2 33 d2 8a f0 8d 85 ?? ?? ?? ?? 8a 56 01 50 53 8b fa c7 03 00 00 00 00 ff 95 ?? ?? ?? ?? 8b c7 25 ff ff 00 00 3d 05 02 00 00}  //weight: 5, accuracy: Low
        $x_5_4 = {68 00 00 00 40 51 ff 15 ?? ?? 40 00 8b f0 83 fe ff 0f 84 ?? ?? 00 00 8d 54 24 18 6a 00 52 68 00 72 00 00 68}  //weight: 5, accuracy: Low
        $x_1_5 = "%s~DF7292.tmp" ascii //weight: 1
        $x_1_6 = "/cgi-bin/CReply.cgi" ascii //weight: 1
        $x_1_7 = "/cgi-bin/ClrF.cgi" ascii //weight: 1
        $x_1_8 = "/cgi-bin/CErr.cgi" ascii //weight: 1
        $x_1_9 = "%s%s%02X-%02X-%02X-%02X-%02X-%02X" ascii //weight: 1
        $x_1_10 = "%s/httpdocs/mm/%sComMand.sec" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Sanpec_C_2147618841_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sanpec.gen!C"
        threat_id = "2147618841"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sanpec"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 ca fc 42 8a 54 15 fc 32 14 06 41 3b cf 88 10 7c e0}  //weight: 1, accuracy: High
        $x_1_2 = {68 14 e0 22 00 ff 75 08 e8}  //weight: 1, accuracy: High
        $x_1_3 = "psec_once" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

