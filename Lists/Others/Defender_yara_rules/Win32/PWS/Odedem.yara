rule PWS_Win32_Odedem_A_2147608912_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Odedem.A"
        threat_id = "2147608912"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Odedem"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {f6 c3 01 c6 02 00 74 2a bf ?? ?? ?? ?? 83 c9 ff}  //weight: 2, accuracy: Low
        $x_2_2 = {83 c9 02 eb 3e 68 ?? ?? ?? ?? 55 e8 ?? ?? 00 00 83 c4 08 85 c0 74 0e 8b 84 24 ?? ?? 00 00 8b 08 83 c9 04 eb 1e}  //weight: 2, accuracy: Low
        $x_1_3 = "l=%s&p=%s&w=%s" ascii //weight: 1
        $x_1_4 = "c=0&w=none" ascii //weight: 1
        $x_1_5 = "c=1&w=%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

