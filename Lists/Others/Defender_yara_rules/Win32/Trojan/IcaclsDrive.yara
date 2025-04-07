rule Trojan_Win32_IcaclsDrive_B_2147938083_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcaclsDrive.B!ibt"
        threat_id = "2147938083"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcaclsDrive"
        severity = "Critical"
        info = "ibt: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {26 00 20 00 69 00 63 00 61 00 63 00 6c 00 73 00 [0-96] 2e 00 62 00 69 00 6e 00 20 00 2f 00 67 00 72 00 61 00 6e 00 74 00 20 00 65 00 76 00 65 00 72 00 79 00 6f 00 6e 00 65 00 3a 00 66 00 20 00 26 00 20 00 65 00 78 00 69 00 74 00}  //weight: 20, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

