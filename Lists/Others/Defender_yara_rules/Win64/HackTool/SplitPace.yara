rule HackTool_Win64_SplitPace_A_2147829391_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/SplitPace.A!dha"
        threat_id = "2147829391"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "SplitPace"
        severity = "High"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "800"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "main.(*Client).NewSession" ascii //weight: 100
        $x_100_2 = "main.(*Client).ProcessingMessages" ascii //weight: 100
        $x_100_3 = "main.(*Client).MakeMessage" ascii //weight: 100
        $x_100_4 = "main.(*Client).getMessagesFromServer" ascii //weight: 100
        $x_100_5 = "main.(*Client).getOneMessageFromServer" ascii //weight: 100
        $x_100_6 = "main.(*Client).Disconnect" ascii //weight: 100
        $x_100_7 = "main.(*Client).Auth" ascii //weight: 100
        $x_100_8 = "main.(*Client).RandomSleep" ascii //weight: 100
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win64_SplitPace_B_2147829392_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/SplitPace.B!dha"
        threat_id = "2147829392"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "SplitPace"
        severity = "High"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "100"
        strings_accuracy = "High"
    strings:
        $x_100_1 = {49 83 f8 0a 75 29 48 be 64 69 73 63 6f 6e 6e 65 0f 1f 84 00 00 00 00 00 48 39 37 0f 85 07 fe ff ff}  //weight: 100, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

