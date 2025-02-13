rule Trojan_Win32_Vidro_A_2147688169_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidro.gen!A"
        threat_id = "2147688169"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidro"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {69 d2 6d 4e c6 41 81 c2 93 30 00 00 89 55 fc c1 ca 08 0f b6 d2 2b c2 05 8c 03 00 00 6a 5e 99 5e f7 fe 80 c2 20}  //weight: 1, accuracy: High
        $x_1_2 = {83 f8 05 0f 8c ?? ?? ?? ?? 8b 07 80 38 23 75 ?? 81 78 01 65 6e 63 23}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

