rule TrojanDropper_WinNT_Wiessy_A_2147634289_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:WinNT/Wiessy.A"
        threat_id = "2147634289"
        type = "TrojanDropper"
        platform = "WinNT: WinNT"
        family = "Wiessy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PsSetLoadImageNotifyRoutine" wide //weight: 1
        $x_1_2 = "\\Device\\ipfltdrv" wide //weight: 1
        $x_1_3 = {0f 20 c0 89 45 fc 25 ff ff fe ff 0f 22 c0}  //weight: 1, accuracy: High
        $x_1_4 = {8a 04 16 8a c8 c0 e9 04 c0 e0 04 0a c8 80 7d ff 00 75 04 c6 45 ff 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

