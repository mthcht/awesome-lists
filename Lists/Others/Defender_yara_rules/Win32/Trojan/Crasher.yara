rule Trojan_Win32_Crasher_2147498144_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Crasher"
        threat_id = "2147498144"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Crasher"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\trash\\VB\\Bus_dest\\bus_des2.vbp" wide //weight: 1
        $x_1_2 = "c:\\a_a_a" wide //weight: 1
        $x_1_3 = "d:\\a_a_a" wide //weight: 1
        $x_1_4 = "E:\\a_a_a" wide //weight: 1
        $x_1_5 = "F:\\a_a_a" wide //weight: 1
        $x_1_6 = "g:\\a_a_a" wide //weight: 1
        $x_1_7 = "O:\\a_a_a" wide //weight: 1
        $x_1_8 = "K:\\a_a_a" wide //weight: 1
        $x_1_9 = "010101001000" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

