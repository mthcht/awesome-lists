rule Trojan_Win32_Dusvext_B_2147648491_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dusvext.B"
        threat_id = "2147648491"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dusvext"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "]&country=" ascii //weight: 1
        $x_1_2 = "&cmpname=" ascii //weight: 1
        $x_1_3 = "adduser.php?uid=" ascii //weight: 1
        $x_1_4 = "poster.php?uid=" ascii //weight: 1
        $x_1_5 = "VertexNet" ascii //weight: 1
        $x_1_6 = "getklogs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

