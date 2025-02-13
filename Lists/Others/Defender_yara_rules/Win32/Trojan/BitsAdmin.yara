rule Trojan_Win32_BitsAdmin_ZZ_2147778016_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BitsAdmin.ZZ"
        threat_id = "2147778016"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BitsAdmin"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "bitsadmin" wide //weight: 1
        $x_1_2 = "/transfer" wide //weight: 1
        $x_1_3 = "/download" wide //weight: 1
        $x_1_4 = "/priority" wide //weight: 1
        $x_1_5 = {5c 00 63 00 24 00 5c 00 [0-48] 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_6 = {5c 00 63 00 24 00 5c 00 [0-48] 2e 00 64 00 6c 00 6c 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_BitsAdmin_ZY_2147836853_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BitsAdmin.ZY"
        threat_id = "2147836853"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BitsAdmin"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = "bitsadmin" wide //weight: 5
        $x_5_2 = "/transfer" wide //weight: 5
        $x_1_3 = {24 00 5c 00 [0-48] 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_4 = {24 00 5c 00 [0-48] 2e 00 64 00 6c 00 6c 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

