rule Trojan_Win32_MpTamperBroadExcl_I_2147888983_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MpTamperBroadExcl.I"
        threat_id = "2147888983"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MpTamperBroadExcl"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "41"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "wmic" wide //weight: 10
        $x_10_2 = "/Namespace:\\\\Root\\Microsoft\\Windows\\Defender" wide //weight: 10
        $x_10_3 = "MSFT_MpPreference" wide //weight: 10
        $x_10_4 = "call Add Exclusion" wide //weight: 10
        $x_1_5 = {65 00 78 00 63 00 6c 00 75 00 73 00 69 00 6f 00 6e 00 65 00 78 00 74 00 65 00 6e 00 73 00 69 00 6f 00 6e 00 3d 00 [0-6] 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_6 = {65 00 78 00 63 00 6c 00 75 00 73 00 69 00 6f 00 6e 00 65 00 78 00 74 00 65 00 6e 00 73 00 69 00 6f 00 6e 00 3d 00 [0-6] 64 00 6c 00 6c 00}  //weight: 1, accuracy: Low
        $x_1_7 = {65 00 78 00 63 00 6c 00 75 00 73 00 69 00 6f 00 6e 00 65 00 78 00 74 00 65 00 6e 00 73 00 69 00 6f 00 6e 00 3d 00 [0-6] 62 00 61 00 74 00}  //weight: 1, accuracy: Low
        $x_1_8 = {65 00 78 00 63 00 6c 00 75 00 73 00 69 00 6f 00 6e 00 65 00 78 00 74 00 65 00 6e 00 73 00 69 00 6f 00 6e 00 3d 00 [0-6] 70 00 73 00 31 00}  //weight: 1, accuracy: Low
        $x_1_9 = {65 00 78 00 63 00 6c 00 75 00 73 00 69 00 6f 00 6e 00 70 00 61 00 74 00 68 00 3d 00 [0-6] 63 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

