rule Trojan_Win32_Golisy_A_2147657909_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Golisy.A"
        threat_id = "2147657909"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Golisy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ".php?page=cpanel&sub=get&id=" ascii //weight: 1
        $x_1_2 = {33 c9 8a 88 99 01 00 00 51 8b 55 ?? 33 c0 8a 82 98 01 00 00 50 8b 4d 00 33 d2 8a 91 97 01 00 00 52 8b 45 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

