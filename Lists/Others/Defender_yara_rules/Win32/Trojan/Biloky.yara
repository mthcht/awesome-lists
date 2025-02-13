rule Trojan_Win32_Biloky_A_2147654627_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Biloky.A"
        threat_id = "2147654627"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Biloky"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "/%s?user=%s&uid=%s&os=%i" ascii //weight: 1
        $x_1_2 = {8b 47 34 8b 7d f8 2b f0 03 cb 2b f8 83 39 00 89 75 f0 74 ?? 8b 41 04 83 f8 08 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

