rule Trojan_Win32_Jevafus_A_2147622790_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Jevafus.A"
        threat_id = "2147622790"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Jevafus"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {74 03 75 01 05 00 e8}  //weight: 2, accuracy: Low
        $x_1_2 = "L2hpcG9pbnRsdGQuY29t" ascii //weight: 1
        $x_1_3 = "VVJMfEhlYWRsaW5lKSMjaHJlZj" ascii //weight: 1
        $x_1_4 = "KG1zbnxsaXZlfG1pY3Jvc29mdCm" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

