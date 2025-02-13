rule Trojan_Win32_Injeber_C_2147719432_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injeber.C!bit"
        threat_id = "2147719432"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injeber"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "i am gonna fuck your tits %s" ascii //weight: 1
        $x_1_2 = "payload is it" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

