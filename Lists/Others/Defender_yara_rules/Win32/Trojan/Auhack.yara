rule Trojan_Win32_Auhack_A_2147642797_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Auhack.A"
        threat_id = "2147642797"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Auhack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 fb 20 7c ?? 80 fb 78 7f ?? 0f be c3 8a 80 f4 60 40 00 83 e0 0f eb ?? 33 c0 0f be 84 c1 ?? ?? ?? ?? c1 f8 04 83 f8 07 89 45 c4 0f 87 ?? ?? ?? ?? ff 24 85}  //weight: 1, accuracy: Low
        $x_1_2 = {41 00 79 00 6f 00 44 00 61 00 6e 00 63 00 65 00 [0-8] 48 00 61 00 63 00 6b 00}  //weight: 1, accuracy: Low
        $x_1_3 = "Nonio" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

