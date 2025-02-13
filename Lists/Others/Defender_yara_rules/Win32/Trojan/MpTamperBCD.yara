rule Trojan_Win32_MpTamperBCD_A_2147778112_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MpTamperBCD.A"
        threat_id = "2147778112"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MpTamperBCD"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {62 00 63 00 64 00 65 00 64 00 69 00 74 00 [0-8] 73 00 65 00 74 00}  //weight: 2, accuracy: Low
        $x_1_2 = "disableelamdrivers true" wide //weight: 1
        $x_1_3 = "disableelamdrivers 1" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

