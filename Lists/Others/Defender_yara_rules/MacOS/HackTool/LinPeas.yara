rule HackTool_MacOS_LinPeas_A_2147923947_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/LinPeas.A!MTB"
        threat_id = "2147923947"
        type = "HackTool"
        platform = "MacOS: "
        family = "LinPeas"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {fe 0f 1f f8 fd 83 1f f8 fd 23 00 d1 00 00 80 b9 7f f1 00 94 fd 83 5f f8 fe 07 41 f8 c0 03 5f d6 fe 0f 1f f8 fd 83 1f f8 fd 23 00 d1 01 04 40 f9 02 10 80 b9 00 00 80 b9 78 f1 00 94 01 00 80 92 3f 00 00 eb 81 00 00 54 77 f1 00 94 00 00 80 b9 e0 03 00 cb}  //weight: 1, accuracy: High
        $x_1_2 = {81 0b 40 f9 e2 03 00 91 5f 00 01 eb c9 01 00 54 fe 0f 1e f8 fd 83 1f f8 fd 23 00 d1 81 13 40 f9 81 01 00 b5 40 07 40 f9 e0 07 00 f9 e0 17 40 f9 e0 0b 00 f9 3b 98 fe 97 fd 83 5f f8 fe 07 42 f8 c0 03 5f d6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

