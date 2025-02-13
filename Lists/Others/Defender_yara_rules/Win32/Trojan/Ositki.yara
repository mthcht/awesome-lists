rule Trojan_Win32_Ositki_A_2147599550_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ositki.A"
        threat_id = "2147599550"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ositki"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {33 ff 47 6a 3b ff 74 24 ?? ff 15 ?? ?? 14 13 8b f0 3b f3 74 53 6a 3b 46 56 ff 15 ?? ?? 14 13 3b c3 8b 0d}  //weight: 4, accuracy: Low
        $x_1_2 = "id=%u&cmd=%d&nt=%d&bv=%s&lt=%s" ascii //weight: 1
        $x_1_3 = "id=%u&cmd=%d&jid=%u&jstat=%u" ascii //weight: 1
        $x_1_4 = "id=%u&cmd=%d&cookie=%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_4_*))) or
            (all of ($x*))
        )
}

