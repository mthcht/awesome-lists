rule Trojan_Win32_Wazabre_A_122214_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Wazabre.A"
        threat_id = "122214"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Wazabre"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 1e 8b 7d f4 8b 75 fc 81 7c 37 fc fe fe fe fe 75 0e ff 75 1c ff 75 e4 e8}  //weight: 1, accuracy: High
        $x_1_2 = {66 c7 05 02 70 40 00 06 00 66 c7 05 06 70 40 00 11 00 66 c7 05 08 70 40 00 12 00 66 c7 05 0a 70 40 00 25 00 68 ?? ?? 40 00 68 ?? ?? 40 00 e8 ?? ?? 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

