rule TrojanDropper_Win32_RibDoor_A_2147743210_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/RibDoor.A!dha"
        threat_id = "2147743210"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "RibDoor"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "EC8A42B380C04901A672094151A40202" ascii //weight: 1
        $x_1_2 = "http://pastebin.com/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

