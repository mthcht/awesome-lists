rule Trojan_Win32_Kibik_B_2147599823_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kibik.B"
        threat_id = "2147599823"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kibik"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {eb e5 89 45 fc ff 75 fc e8 ?? ?? 00 00 03 45 fc 96 83 ee 34 4e 8a 06 3c 3e 75 05 e9 ?? 01 00 00 46 89 75 ec}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

