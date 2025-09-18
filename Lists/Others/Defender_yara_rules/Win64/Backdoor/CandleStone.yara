rule Backdoor_Win64_CandleStone_A_2147952472_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/CandleStone.A!dha"
        threat_id = "2147952472"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "CandleStone"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "{AD6FFA8B-5379-45F9-8695-E883DF622484}" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

