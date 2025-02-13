rule Trojan_Win32_Puppetzombie_2147601136_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Puppetzombie"
        threat_id = "2147601136"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Puppetzombie"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {05 00 00 00 67 62 6a 73 6a 00 00 00 ff ff ff ff 05 00 00 00 63 71 6a 73 6a 00 00 00 ff ff ff ff 04 00 00 00 73 78 6a 73 00 00 00}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

