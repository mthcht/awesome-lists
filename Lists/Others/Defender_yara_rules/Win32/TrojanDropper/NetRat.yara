rule TrojanDropper_Win32_NetRat_V_2147754849_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/NetRat.V!MTB"
        threat_id = "2147754849"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "NetRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\blowfish.dll" ascii //weight: 1
        $x_1_2 = "o CreateObject(\"Wscript.Shell\").Run \"cmd" ascii //weight: 1
        $x_1_3 = {73 00 26 00 20 00 77 00 73 00 63 00 72 00 69 00 70 00 74 00 20 00 25 00 61 00 70 00 70 00 64 00 61 00 74 00 61 00 25 00 5c 00 [0-21] 2e 00 76 00 62 00}  //weight: 1, accuracy: Low
        $x_1_4 = {73 26 20 77 73 63 72 69 70 74 20 25 61 70 70 64 61 74 61 25 5c [0-21] 2e 76 62}  //weight: 1, accuracy: Low
        $x_1_5 = {73 00 26 00 20 00 64 00 65 00 6c 00 20 00 25 00 61 00 70 00 70 00 64 00 61 00 74 00 61 00 25 00 5c 00 [0-21] 2e 00 76 00 62 00}  //weight: 1, accuracy: Low
        $x_1_6 = {73 26 20 64 65 6c 20 25 61 70 70 64 61 74 61 25 5c [0-21] 2e 76 62}  //weight: 1, accuracy: Low
        $x_1_7 = "owershell -ep bypass -f" ascii //weight: 1
        $x_1_8 = {79 00 70 00 61 00 73 00 73 00 20 00 2d 00 66 00 20 00 43 00 3a 00 5c 00 54 00 45 00 4d 00 50 00 5c 00 63 00 76 00 65 00 [0-5] 2e 00 70 00 73 00 31 00}  //weight: 1, accuracy: Low
        $x_1_9 = {79 70 61 73 73 20 2d 66 20 43 3a 5c 54 45 4d 50 5c 63 76 65 [0-5] 2e 70 73 31}  //weight: 1, accuracy: Low
        $x_1_10 = {43 00 3a 00 5c 00 54 00 45 00 4d 00 50 00 5c 00 [0-21] 2e 00 74 00 6d 00 70 00 5c 00 62 00 6c 00 6f 00 77 00 66 00 69 00 73 00 68 00 2e 00 64 00 6c 00 6c 00}  //weight: 1, accuracy: Low
        $x_1_11 = {43 3a 5c 54 45 4d 50 5c [0-21] 2e 74 6d 70 5c 62 6c 6f 77 66 69 73 68 2e 64 6c 6c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

