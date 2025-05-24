rule Trojan_Win32_SocGholish_HA_2147942134_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SocGholish.HA!MTB"
        threat_id = "2147942134"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SocGholish"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {66 00 6f 00 72 00 65 00 61 00 63 00 68 00 2d 00 6f 00 62 00 6a 00 65 00 63 00 74 00 20 00 7b 00 5b 00 63 00 68 00 61 00 72 00 5d 00 28 00 5b 00 69 00 6e 00 74 00 5d 00 28 00 27 00 [0-64] 27 00 20 00 2b 00 20 00 27 00 [0-64] 27 00 29 00 2e 00 73 00 75 00 62 00 73 00 74 00 72 00 69 00 6e 00 67 00 28 00 24 00 28 00 24 00 5f 00 20 00 2a 00 20 00 33 00 29 00 2c 00 20 00 33 00 29 00 20 00 2d 00 20 00 [0-6] 29 00 7d 00 29 00 [0-208] 2e 00 6c 00 6f 00 67 00 27 00 20 00 2d 00 72 00 61 00 77 00 29 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

