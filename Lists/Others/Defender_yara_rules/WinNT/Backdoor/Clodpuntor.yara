rule Backdoor_WinNT_Clodpuntor_A_2147595286_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:WinNT/Clodpuntor.A!sys"
        threat_id = "2147595286"
        type = "Backdoor"
        platform = "WinNT: WinNT"
        family = "Clodpuntor"
        severity = "Critical"
        info = "sys: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 fc 69 c0 1c 01 00 00 8b 44 30 0c 89 45 f0 68 37 37 36 36}  //weight: 1, accuracy: High
        $x_1_2 = {c7 07 ff ff 00 00 8d 7e f9 3b d7 73 45 8d 42 05 81 78 fb 8a 41 09 3c 75 12 80 78 ff 06 75 0c 66 81 38 0f 84 75 05 8d 48 fe eb 02}  //weight: 1, accuracy: High
        $x_1_3 = {fa 0f 20 c0 50 25 ff ff fe ff 0f 22 c0 66 c7 01 0c ff 58 0f 22 c0 fb}  //weight: 1, accuracy: High
        $x_1_4 = {fa 0f 20 c0 50 25 ff ff fe ff 0f 22 c0 66 c7 01 3b c0 58 0f 22 c0 fb 8b d1 eb d3 8b 45 f0 85 c0 75 05 b8 82 01 00 c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

