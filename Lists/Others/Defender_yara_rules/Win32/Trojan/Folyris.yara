rule Trojan_Win32_Folyris_A_2147683774_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Folyris.A"
        threat_id = "2147683774"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Folyris"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "uid:%s|taskid:%i" ascii //weight: 1
        $x_1_2 = {c7 03 74 72 75 65 c6 43 04 00 eb 0c c7 03 66 61 6c 73 66 c7 43 04 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

