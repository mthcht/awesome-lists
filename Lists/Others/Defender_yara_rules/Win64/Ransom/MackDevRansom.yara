rule Ransom_Win64_MackDevRansom_A_2147972373_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/MackDevRansom.A!MSR"
        threat_id = "2147972373"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "MackDevRansom"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MACKDEV RANSOMWARE v7.1" ascii //weight: 1
        $x_1_2 = "main.disableDefender" ascii //weight: 1
        $x_1_3 = "main.encryptDrive" ascii //weight: 1
        $x_1_4 = "main.createRansomNote" ascii //weight: 1
        $x_1_5 = "MackDEV_README.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

