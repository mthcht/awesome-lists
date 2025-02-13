rule Trojan_Win32_Rebrela_A_2147651476_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rebrela.A"
        threat_id = "2147651476"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rebrela"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "uid=%s&ip=%s&username=%s" ascii //weight: 1
        $x_1_2 = {ff 56 04 8b d8 55 6a 08 53 ff 56 08 8d 96 ?? ?? 00 00 8b f8 52 6a 00 6a 06 ff 56 0c 6a 00 6a 00 6a 00 6a 06 50 ff 56 10 8b 8e ?? ?? 00 00 8d 96 ?? ?? 00 00 52 03 c8 6a 00 6a 06}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

