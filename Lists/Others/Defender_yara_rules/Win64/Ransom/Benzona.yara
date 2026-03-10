rule Ransom_Win64_Benzona_A_2147964378_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Benzona.A!dha"
        threat_id = "2147964378"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Benzona"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RECOVERY_INFO.txt" ascii //weight: 1
        $x_1_2 = "wallpaper.png" ascii //weight: 1
        $x_1_3 = ".benzona" ascii //weight: 1
        $x_1_4 = "RSA encryption failed" ascii //weight: 1
        $x_1_5 = "wbadmin delete catalog -quiet" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

