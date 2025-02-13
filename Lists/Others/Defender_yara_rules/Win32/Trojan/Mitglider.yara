rule Trojan_Win32_Mitglider_CCD_2147594031_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Mitglider.CCD"
        threat_id = "2147594031"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Mitglider"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 8b ec 8b 7d 08 f7 d0 eb 0b 47 80 77 ff 05 d0 47 ff f6 57 ff 3b 7d 0c 75 f0 c9 c2 08 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

