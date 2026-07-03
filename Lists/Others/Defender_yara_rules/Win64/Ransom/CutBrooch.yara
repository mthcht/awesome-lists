rule Ransom_Win64_CutBrooch_A_2147972807_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/CutBrooch.A!dha"
        threat_id = "2147972807"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "CutBrooch"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "bigBangHybridEncryption" ascii //weight: 1
        $x_1_2 = "BigBangExtortMain" ascii //weight: 1
        $x_1_3 = "bigBangSingleFileExtortion" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

