rule Trojan_Win32_Woreflint_AS_2147780096_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Woreflint.AS!MTB"
        threat_id = "2147780096"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Woreflint"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {11 04 17 58 20 00 01 00 00 5d 13 04 11 05 07 11 04 91 58 20 00 01 00 00 5d 13 05 07 11 04 91 ?? 07 11 04 07 11 05 91 9c 07 11 05 09 9c 07 11 04 91 07 11 05 91 58 20 00 01 00 00}  //weight: 10, accuracy: Low
        $x_5_2 = "[AMINE]" ascii //weight: 5
        $x_4_3 = "C:\\Users\\madar\\" ascii //weight: 4
        $x_3_4 = "BBBB2" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*))) or
            ((1 of ($x_10_*) and 1 of ($x_3_*))) or
            ((1 of ($x_10_*) and 1 of ($x_4_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

