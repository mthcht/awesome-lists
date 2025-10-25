rule Trojan_Win32_AnonDoor_AMTB_2147956019_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AnonDoor!AMTB"
        threat_id = "2147956019"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AnonDoor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "MSL37CNASY6324.dll" ascii //weight: 2
        $x_2_2 = "$a786cdbd-27c7-469e-8e33-90e3d8d0220d" ascii //weight: 2
        $x_1_3 = "2.4.9.7" ascii //weight: 1
        $x_1_4 = "KEEDSPQ2XX.Class1" wide //weight: 1
        $x_1_5 = "MR9S4CGRGBY.Class1" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

