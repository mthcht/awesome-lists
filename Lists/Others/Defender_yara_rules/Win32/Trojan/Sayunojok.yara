rule Trojan_Win32_Sayunojok_A_2147697339_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sayunojok.A"
        threat_id = "2147697339"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sayunojok"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "WS\\Help\\cnwb.html" ascii //weight: 2
        $x_2_2 = "/synjkc.com/asp/mail.asp?QQnumber=" ascii //weight: 2
        $x_2_3 = "synjkc$" wide //weight: 2
        $x_2_4 = "52900523aa!@#" wide //weight: 2
        $x_1_5 = "cnssa_deinit" ascii //weight: 1
        $x_1_6 = {68 ff 00 00 00 89 4c 24 28 b9 11 00 00 00 f3 ab b9 64 00 00 00 8d bc 24 a0 01 00 00 52 68}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

