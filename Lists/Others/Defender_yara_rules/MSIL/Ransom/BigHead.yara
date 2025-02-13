rule Ransom_MSIL_BigHead_ABH_2147850641_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/BigHead.ABH!MTB"
        threat_id = "2147850641"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BigHead"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {16 13 04 2b 14 00 02 09 11 04 9a 04 28 ?? ?? ?? 06 00 00 11 04 17 58 13 04 11 04 09 8e 69 fe 04 13 09 11 09 2d df}  //weight: 2, accuracy: Low
        $x_1_2 = "slam_ransomware_builder\\ConsoleApp2\\ConsoleApp2\\obj\\Debug\\ConsoleApp2.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

