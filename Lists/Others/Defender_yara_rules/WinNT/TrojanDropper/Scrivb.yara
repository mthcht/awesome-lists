rule TrojanDropper_WinNT_Scrivb_A_2147638676_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:WinNT/Scrivb.A"
        threat_id = "2147638676"
        type = "TrojanDropper"
        platform = "WinNT: WinNT"
        family = "Scrivb"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {fa 0f 20 c0 25 ff ff fe ff 0f 22 c0 [0-15] 0f 20 c0 0d 00 00 01 00 0f 22 c0 fb}  //weight: 1, accuracy: Low
        $x_1_2 = {6f 6e 20 65 72 72 6f 72 20 72 65 73 75 6d 65 20 6e 65 78 74 3a [0-6] 3d 20 41 72 72 61 79 28}  //weight: 1, accuracy: Low
        $x_1_3 = {5c 00 57 00 49 00 4e 00 44 00 4f 00 57 00 53 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 [0-14] 2e 00 76 00 62 00 73 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

