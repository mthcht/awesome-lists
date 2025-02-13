rule TrojanDropper_Win32_Divapad_A_2147624648_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Divapad.A"
        threat_id = "2147624648"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Divapad"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "\\\\.\\Global\\ip_fw" ascii //weight: 2
        $x_2_2 = "\\DRIVERS\\ip_fw.sys" ascii //weight: 2
        $x_1_3 = "kaspersky" ascii //weight: 1
        $x_1_4 = "liveupdate" ascii //weight: 1
        $x_1_5 = "freeav" ascii //weight: 1
        $x_1_6 = "avgate" ascii //weight: 1
        $x_2_7 = {eb 53 6a 00 8d 4d f4 51 ff 75 fc 53 ff 75 fc 53 68 08 21 24 43 50}  //weight: 2, accuracy: High
        $x_2_8 = {66 a5 a4 8b 75 fc 66 89 46 14 66 ff 45 d6 33 c0 40 89 46 16 66 89 46 1a 83 c6 1c 33 c0 8b fe ab}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((4 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

