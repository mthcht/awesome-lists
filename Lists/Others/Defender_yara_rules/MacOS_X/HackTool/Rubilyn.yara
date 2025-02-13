rule HackTool_MacOS_X_Rubilyn_A_2147681916_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS_X/Rubilyn.A!kext"
        threat_id = "2147681916"
        type = "HackTool"
        platform = "MacOS_X: "
        family = "Rubilyn"
        severity = "High"
        info = "kext: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {49 ff c6 4c 89 f7 e8 00 00 00 00 49 89 c7 4c 89 eb 8a 0b 31 c0 84 c9 74 1e 4c 8d 6b 01 44 38 e1 75 ec}  //weight: 10, accuracy: High
        $x_10_2 = {31 c0 89 c3 4c 89 7d c8 4c 63 fb 43 8a 04 3e 48 8b 4d c8 42 32 04 29 0f be c0 89 45 d4}  //weight: 10, accuracy: High
        $x_2_3 = "rubilyn" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

