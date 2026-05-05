rule Ransom_Win64_Nblock_YBG_2147968449_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Nblock.YBG!MTB"
        threat_id = "2147968449"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Nblock"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "YOUR F!L3S @R3 G0N" ascii //weight: 1
        $x_1_2 = ".locked" ascii //weight: 1
        $x_1_3 = "background.bmp" ascii //weight: 1
        $x_1_4 = "say Hi to NBLock" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

