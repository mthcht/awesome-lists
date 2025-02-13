rule Trojan_Win32_Winusp_A_2147661743_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Winusp.A"
        threat_id = "2147661743"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Winusp"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {20 37 ef c6 c7 ?? ?? b9 79 37 9e 8b 4d 0c 8b 11 89 55 fc 8b 45 0c 8b 48 04 89 4d f0}  //weight: 1, accuracy: Low
        $x_1_2 = {c1 e0 04 0f b6 4d ?? c1 f9 02 0b c1 8b 55 ?? 88 02 8b 45 ?? 83 c0 01 89 45 fc 83 7d 10 00}  //weight: 1, accuracy: Low
        $x_1_3 = "%d:%d:%d %s err:%d" ascii //weight: 1
        $x_1_4 = "?i=%s&m=u&f=0&d=%d" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

