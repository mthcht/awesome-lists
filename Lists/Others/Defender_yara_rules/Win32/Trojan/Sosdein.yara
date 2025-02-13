rule Trojan_Win32_Sosdein_A_2147646261_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sosdein.A"
        threat_id = "2147646261"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sosdein"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {74 1b 6a 02 68 ?? fe ff ff 57 e8 ?? ?? ?? 00 83 c4 0c 85 c0 57 74 0a}  //weight: 3, accuracy: Low
        $x_1_2 = "result?hl=en&meta=%s" ascii //weight: 1
        $x_1_3 = "%susrer__%d.ini" ascii //weight: 1
        $x_1_4 = "%d~CPU/%u~MHz" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

