rule Trojan_Win32_Clopdor_A_2147629363_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Clopdor.A"
        threat_id = "2147629363"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Clopdor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {99 b9 a8 03 00 00 f7 f9 8b 55 08}  //weight: 2, accuracy: High
        $x_1_2 = {05 d0 07 00 00 50 ff 15}  //weight: 1, accuracy: High
        $x_2_3 = {6a 00 6a 00 6a 00 8b 55 ec 52 ff 15 ?? ?? 00 10 6a 05}  //weight: 2, accuracy: Low
        $x_2_4 = {8a 0a 32 8c 05 ?? ?? ff ff 8b 95 ?? ?? ff ff 03 95 ?? ?? ff ff 88 0a eb bd 6a 00}  //weight: 2, accuracy: Low
        $x_1_5 = "!chckOK!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

