rule Trojan_Win32_Quazibit_A_2147688936_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Quazibit.A"
        threat_id = "2147688936"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Quazibit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c6 00 68 81 c1 ?? ?? ?? ?? 89 48 01 c6 40 05 c3 8b 45 cc 89 45 f4 89 45 f8 8b 45 b8 68 e1 d3 d4 5e 6a 02}  //weight: 1, accuracy: Low
        $x_1_2 = {ff d0 68 df f4 9a 1d 6a 06 89 45 fc e8 ?? ?? ?? ?? 59 59 56 6a 02 ff 75 0c ff 75 08 ff 75 fc ff d0 be 0c fb 14 73 56 6a 06}  //weight: 1, accuracy: Low
        $x_1_3 = "fipubfg.rkr" ascii //weight: 1
        $x_1_4 = "*.jnyyrg" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

