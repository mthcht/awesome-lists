rule Trojan_Win32_Heantyk_A_2147606569_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Heantyk.A"
        threat_id = "2147606569"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Heantyk"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 45 fc ff 75 f8 50 e8 ?? ?? 00 00 eb 87 50 e8 ?? ?? 00 00 c7 04 24 ?? ?? 40 00 ff 75 f4 8d 45 f8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

