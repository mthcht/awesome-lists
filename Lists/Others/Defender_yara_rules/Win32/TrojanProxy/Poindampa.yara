rule TrojanProxy_Win32_Poindampa_A_2147696548_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Poindampa.A"
        threat_id = "2147696548"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Poindampa"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "DEFAULT_CONNECT_STRING=ads.fusiontrk.comXXXXX" ascii //weight: 2
        $x_2_2 = {43 44 43 5f 56 4f 52 44 4d 45 5f 49 4e 53 54 41 4e 43 45 5f 4d 55 54 45 58 5f 08 00}  //weight: 2, accuracy: Low
        $x_2_3 = {53 6f 66 74 77 61 72 65 5c 41 70 70 44 6f 6d 61 69 6e 00 52 75 6e 42 65 66 6f 72 65}  //weight: 2, accuracy: High
        $x_1_4 = "Checkpoint end of RequestHeaders.insert() crap." ascii //weight: 1
        $x_1_5 = "ServerLoop(): Connection succeeded immediately; WTF?" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

