rule Ransom_Win32_Cendode_A_2147690868_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Cendode.A"
        threat_id = "2147690868"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Cendode"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "The only way to restore them - purchase the unique unlock code." ascii //weight: 1
        $x_1_2 = "BUYUNLOCKCODE.txt" ascii //weight: 1
        $x_1_3 = "allfileslocked" ascii //weight: 1
        $x_1_4 = ".enc0ded" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

