rule Trojan_Win32_Kradod_A_2147680138_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kradod.A"
        threat_id = "2147680138"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kradod"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c6 45 ce 70 c6 45 cf 69 c6 45 d0 6e c6 45 d1 67 c6 45 d2 20 c6 45 d3 31 c6 45 d4 2e c6 45 d5 32 c6 45 d6 2e c6 45 d7 33 c6 45 d8 2e c6 45 d9 34 c6 45 da 20 c6 45 db 2d c6 45 dc 6e c6 45 dd 20 c6 45 de 31 c6 45 df 20 c6 45 e0 2d c6 45 e1 77}  //weight: 1, accuracy: High
        $x_1_2 = {c6 45 f5 75 c6 45 f6 63 c6 45 f7 6b c6 45 f8 ?? c6 45 f9 ?? c6 45 fa ?? e8}  //weight: 1, accuracy: Low
        $x_1_3 = "svchost.exe -k netsvcs" ascii //weight: 1
        $x_1_4 = "9B345CD7-B006-4b3a-AFC6-9A61C5491BCA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

