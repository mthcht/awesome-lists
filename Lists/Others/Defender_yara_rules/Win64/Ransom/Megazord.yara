rule Ransom_Win64_Megazord_SA_2147899925_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Megazord.SA!MTB"
        threat_id = "2147899925"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Megazord"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\release\\deps\\megazord.pdb" ascii //weight: 1
        $x_1_2 = "SystemFunction036" ascii //weight: 1
        $x_1_3 = "BCryptGenRandom" ascii //weight: 1
        $x_1_4 = "\\Users\\Public\\C:\\$RECYCLE.BIN" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

