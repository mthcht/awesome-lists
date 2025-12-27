rule Trojan_Win32_HoldingHands_AMTB_2147959172_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/HoldingHands!AMTB"
        threat_id = "2147959172"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "HoldingHands"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "D:\\Workspace\\HoldingHands-develop\\HoldingHands-develop\\Door\\x64\\Release\\Run_New.pdb" ascii //weight: 3
        $x_3_2 = "D:\\Workspace\\HoldingHands-develop\\HoldingHands-develop\\Door\\x64\\Release\\BackDoor.pdb" ascii //weight: 3
        $x_1_3 = "Chengdu Lingxu Technology Co., Ltd.0" ascii //weight: 1
        $x_1_4 = "$Shanghai Liandu Technology Co., Ltd.1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

