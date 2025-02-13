rule Trojan_Win32_Jowbaki_A_2147712065_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Jowbaki.A"
        threat_id = "2147712065"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Jowbaki"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = "lms_jowbak" wide //weight: 4
        $x_2_2 = {68 00 08 00 00 e8 ?? ?? 00 00 59 8b d8 68 d0 07 00 00 ff 15}  //weight: 2, accuracy: Low
        $x_2_3 = {75 12 8b 71 14 c1 e6 1d c1 fe 1f eb 07 33 f6 46 eb 02 33 f6 8b 41 14 c1 e0 1e c1 f8 1f 3b c6}  //weight: 2, accuracy: High
        $x_1_4 = "/utils/inet_id_notify.php" wide //weight: 1
        $x_1_5 = "rmansys.ru" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

