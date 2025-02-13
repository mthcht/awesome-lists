rule Trojan_Win32_Pigax_A_2147621727_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pigax.gen!A"
        threat_id = "2147621727"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pigax"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "oqs.vdc" ascii //weight: 2
        $x_1_2 = {eb 0f 8b 44 24 08 0f b6 04 08 83 f0 ?? 88 04 0b 41 39 d1 72 ed}  //weight: 1, accuracy: Low
        $x_1_3 = {eb 15 0f b7 45 fe 01 f8 0f be 10 0f be 4f 02 31 ca 88 10}  //weight: 1, accuracy: High
        $x_1_4 = {6a 00 6a 0a ff 75 fc e8 ?? ?? ?? ?? 09 c0 75 6f}  //weight: 1, accuracy: Low
        $x_1_5 = {66 89 45 10 66 81 7d 10 94 01 75 0e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

