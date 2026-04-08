rule Joke_Win32_ScreenMate_2147762940_0
{
    meta:
        author = "defender2yara"
        detection_name = "Joke:Win32/ScreenMate"
        threat_id = "2147762940"
        type = "Joke"
        platform = "Win32: Windows 32-bit platform"
        family = "ScreenMate"
        severity = "Mid"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Message Mate" ascii //weight: 1
        $x_1_2 = "Screen Mate" ascii //weight: 1
        $x_1_3 = "Dev\\Code\\Productions\\MannyNewMessageMates\\hotstuff\\scene.cpp" ascii //weight: 1
        $x_1_4 = "We>hi" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

