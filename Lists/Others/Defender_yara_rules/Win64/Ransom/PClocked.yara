rule Ransom_Win64_PClocked_SL_2147965510_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/PClocked.SL!MTB"
        threat_id = "2147965510"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "PClocked"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".pclocked" ascii //weight: 1
        $x_1_2 = "RedBlackChoose your side:Spinning the wheel" ascii //weight: 1
        $x_1_3 = "Invalid amount. The house doesn't take credit!" ascii //weight: 1
        $x_1_4 = "You are bankrupt! Game Over" ascii //weight: 1
        $x_1_5 = "Shutting down engine... Press Enter to exit" ascii //weight: 1
        $x_1_6 = "runasElevation request failed" ascii //weight: 1
        $x_1_7 = "vssadmindeleteshadows/all/quietError" ascii //weight: 1
        $x_1_8 = "try turning off your AV and rerun the software" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

