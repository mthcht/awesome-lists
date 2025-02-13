rule Ransom_Win32_Meteoritan_GK_2147853347_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Meteoritan.GK!MTB"
        threat_id = "2147853347"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Meteoritan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "where_are_your_files.txt" ascii //weight: 1
        $x_1_2 = "meteoritan6570@yandex.ru" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

