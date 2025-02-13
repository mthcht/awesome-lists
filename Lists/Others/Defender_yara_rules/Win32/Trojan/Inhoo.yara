rule Trojan_Win32_Inhoo_A_2147599276_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Inhoo.A"
        threat_id = "2147599276"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Inhoo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 3e 8d 45 fc 8b 35 ?? 10 00 10 50 6a 40 6a 40 c7 45 e8 ?? ?? 00 10 ff 75 08 c7 45 ec ?? ?? 00 10 53 ff d6 85 c0 74 2b}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 00 ff 35 ?? ?? 00 10 68 ?? ?? 00 10 6a 07 ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

