rule Trojan_Win32_Unihorn_A_2147633090_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Unihorn.A"
        threat_id = "2147633090"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Unihorn"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {83 7d f8 ff 74 2a 6a 00 8d 95 ?? ?? ff ff 52 68 ac 01 00 00 68 ?? ?? ?? ?? 8b 45 f8 50 ff 15}  //weight: 2, accuracy: Low
        $x_2_2 = {c7 85 10 fd ff ff 00 00 00 00 68 c8 02 00 00 6a 00 8d 85 14 fd ff ff 50 e8}  //weight: 2, accuracy: High
        $x_1_3 = "a=load&id=%s&dr=%d&rr=%d" ascii //weight: 1
        $x_1_4 = "</bot_endcmd>" ascii //weight: 1
        $x_1_5 = "unikorn-v" ascii //weight: 1
        $x_1_6 = "oid=%d&s=%d&u=%s&cid=%s-%08X&ru=%d&rt=%d&t=%d&bid=%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

