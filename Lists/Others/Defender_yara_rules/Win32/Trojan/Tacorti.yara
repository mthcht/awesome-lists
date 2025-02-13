rule Trojan_Win32_Tacorti_A_2147630573_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tacorti.A"
        threat_id = "2147630573"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tacorti"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {f6 c3 01 74 22 8d 45 ec 8b 55 fc 0f b6 54 1a ff 03 55 f8 03 55 f4}  //weight: 1, accuracy: High
        $x_1_2 = {50 8b 07 8b 40 14 03 45 f0 50 8b 07 8b 40 0c 03 45 ec 50 53 ff 15 4c 18 41 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

