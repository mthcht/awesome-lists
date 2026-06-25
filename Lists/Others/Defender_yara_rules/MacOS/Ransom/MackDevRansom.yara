rule Ransom_MacOS_MackDevRansom_A_2147972374_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MacOS/MackDevRansom.A!MSR"
        threat_id = "2147972374"
        type = "Ransom"
        platform = "MacOS: "
        family = "MackDevRansom"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "main.infectKext" ascii //weight: 1
        $x_1_2 = "main.disableGatekeeper" ascii //weight: 1
        $x_1_3 = "MACKDEV RANSOMWARE v7.1" ascii //weight: 1
        $x_1_4 = "main.encryptDirectory" ascii //weight: 1
        $x_1_5 = "MackDEV_README.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

