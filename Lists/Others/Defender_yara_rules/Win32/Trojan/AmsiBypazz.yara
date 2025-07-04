rule Trojan_Win32_AmsiBypazz_A_2147945457_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AmsiBypazz.A!MTB"
        threat_id = "2147945457"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AmsiBypazz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "[Ref].Assembly.GetType" wide //weight: 1
        $x_1_2 = ".getfield" wide //weight: 1
        $x_1_3 = {69 00 6e 00 69 00 74 00 66 00 61 00 69 00 6c 00 65 00 64 00 [0-16] 24 00}  //weight: 1, accuracy: Low
        $x_1_4 = {76 00 61 00 6c 00 75 00 65 00 [0-16] 24 00 6e 00 75 00 6c 00 6c 00 2c 00 24 00 74 00 72 00 75 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

