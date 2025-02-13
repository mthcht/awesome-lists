rule Trojan_Win32_Gasti_BT_2147831375_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gasti.BT!MTB"
        threat_id = "2147831375"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gasti"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "m.mssqlnewpro.com/mssql88/upload.php" ascii //weight: 4
        $x_4_2 = "rrr.txt" ascii //weight: 4
        $x_2_3 = "WebKitFormBoundary82XB4u9Ywg0A6zUm" ascii //weight: 2
        $x_1_4 = "[total_blob_num]" ascii //weight: 1
        $x_1_5 = "[hashCode]" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

