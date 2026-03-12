rule Ransom_Win32_NopName_AMTB_2147964575_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/NopName!AMTB"
        threat_id = "2147964575"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "NopName"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "@======== You have been encrypted by NopName ========" ascii //weight: 2
        $x_2_2 = "@.rams0n" ascii //weight: 2
        $x_1_3 = "@README.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

