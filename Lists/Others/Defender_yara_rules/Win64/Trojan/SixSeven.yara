rule Trojan_Win64_SixSeven_A_2147981888_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/SixSeven.A!dha"
        threat_id = "2147981888"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "SixSeven"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Invalid parameters: entry name and executable path" wide //weight: 1
        $x_1_2 = "in su function and url is :" ascii //weight: 1
        $x_1_3 = "in get_user_id after from file" ascii //weight: 1
        $x_1_4 = "\\log\\log_58742686" wide //weight: 1
        $x_1_5 = "\\log\\j36ns82b.evt" wide //weight: 1
        $x_1_6 = "/vdQozUuWglkNrRhqngOt" ascii //weight: 1
        $x_1_7 = "/lynSXFtmsgKv83QUrs9J" ascii //weight: 1
        $x_1_8 = "S43lMZQSe3myWeP9" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

