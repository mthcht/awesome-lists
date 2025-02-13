rule TrojanClicker_Win32_Popagerty_A_2147649402_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/Popagerty.A"
        threat_id = "2147649402"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "Popagerty"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "popupguide\\data.db" ascii //weight: 2
        $x_2_2 = "counter.pop-upguide.com" ascii //weight: 2
        $x_2_3 = "popupguide\\source\\MainU.pas" ascii //weight: 2
        $x_1_4 = "ilikeclick.com/track/click.php" ascii //weight: 1
        $x_1_5 = "popupguide_02" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

