rule Ransom_Win32_Aicat_A_2147809789_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Aicat.A!MTB"
        threat_id = "2147809789"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Aicat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8a 06 88 07 8a 46 01 88 47 01 8a 46 02 88 47 02 8b 45 08}  //weight: 10, accuracy: High
        $x_3_2 = "xxxx.onion" ascii //weight: 3
        $x_3_3 = "\\Rx2o7d.txt" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

