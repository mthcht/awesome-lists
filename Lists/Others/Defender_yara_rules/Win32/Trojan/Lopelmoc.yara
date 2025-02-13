rule Trojan_Win32_Lopelmoc_A_2147640285_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lopelmoc.A"
        threat_id = "2147640285"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lopelmoc"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 f9 7e 7d 25 0f be 55 cf 83 fa 4f 7d 0c 0f be 45 cf 83 c0 2f}  //weight: 1, accuracy: High
        $x_1_2 = {68 58 03 00 00 e8 ?? ?? ?? ?? 83 c4 04 89 45 fc 83 7d fc 00 0f 84 ?? ?? 00 00 6a ff 8b 45 08 50 68 07 01 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = "UPDATE properties SET id=?" ascii //weight: 1
        $x_1_4 = "handler.php" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

