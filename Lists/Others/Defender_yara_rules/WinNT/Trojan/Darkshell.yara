rule Trojan_WinNT_Darkshell_C_2147652085_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Darkshell.C"
        threat_id = "2147652085"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Darkshell"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b9 4e e6 40 bb 74 04 3b c1 75 1a a1 28 0c 01 00 8b 00 35 80 0d 01 00 a3 80 0d 01 00 75 07 8b c1}  //weight: 1, accuracy: High
        $x_1_2 = {ff 35 94 0d 01 00 ff 35 8c 0d 01 00 ff 15 20 0c 01 00 0f b7 05 a0 0d 01 00 50 ff 35 a4 0d 01 00}  //weight: 1, accuracy: High
        $x_1_3 = {25 ff ff fe ff 0f 22 c0 8b 06 89 03 0f 20 c0 0d 00 00 01 00 0f 22 c0 fb 33 db eb 1b bb 0d 00 00}  //weight: 1, accuracy: High
        $x_1_4 = "asgfdsgetyythutrsfaee23456456jtyj67ur6yrhty" wide //weight: 1
        $x_1_5 = "\\??\\Dark2118" wide //weight: 1
        $x_1_6 = "\\dEvIcE\\VoiceDevice" wide //weight: 1
        $x_1_7 = "_darkshell\\i386\\DarkShell.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

