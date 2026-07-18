rule Ransom_Win64_Doomma_YDQ_2147973567_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Doomma.YDQ!MTB"
        threat_id = "2147973567"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Doomma"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "vssadmindeleteshadows/all/quiet" ascii //weight: 1
        $x_1_2 = "files have been encrypted" ascii //weight: 1
        $x_1_3 = "TO RECOVER YOUR FILES" ascii //weight: 1
        $x_1_4 = "permanently destroyed" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

