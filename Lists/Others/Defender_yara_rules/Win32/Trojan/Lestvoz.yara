rule Trojan_Win32_Lestvoz_A_2147623030_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lestvoz.A"
        threat_id = "2147623030"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lestvoz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[MailPassword]=" wide //weight: 1
        $x_1_2 = "[DetectIP]=" wide //weight: 1
        $x_1_3 = "%[Start Menu]" wide //weight: 1
        $x_1_4 = "align=\"center\" class=\"style5\">" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

