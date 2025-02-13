rule BrowserModifier_Win32_Mispin_131436_0
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Mispin"
        threat_id = "131436"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Mispin"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "%s\\MiniPS\\MiniPSD" ascii //weight: 2
        $x_2_2 = "minips.co.kr" ascii //weight: 2
        $x_1_3 = "mnm=clickstory" ascii //weight: 1
        $x_1_4 = "ilikeclick" ascii //weight: 1
        $x_1_5 = {68 74 74 70 3a 2f 2f 6e 61 76 65 72 00 00 00 00 26 6d 5f 75 72 6c 3d}  //weight: 1, accuracy: High
        $x_1_6 = "ValueFromClick=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

