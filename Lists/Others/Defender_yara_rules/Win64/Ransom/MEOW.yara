rule Ransom_Win64_MEOW_AMTB_2147971671_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/MEOW!AMTB"
        threat_id = "2147971671"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "MEOW"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MEOW RANSOMWARE" ascii //weight: 1
        $x_1_2 = ".meow" ascii //weight: 1
        $x_1_3 = "C:\\MEOW_README.txt" ascii //weight: 1
        $x_1_4 = "meow_bg.png" ascii //weight: 1
        $x_1_5 = "wmic shadowcopy delete" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

