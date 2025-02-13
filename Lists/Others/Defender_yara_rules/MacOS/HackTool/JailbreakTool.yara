rule HackTool_MacOS_JailbreakTool_AC_2147832798_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/JailbreakTool.AC!MTB"
        threat_id = "2147832798"
        type = "HackTool"
        platform = "MacOS: "
        family = "JailbreakTool"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "iPwnder32" ascii //weight: 1
        $x_1_2 = "heap spray" ascii //weight: 1
        $x_1_3 = "limera1n exploit (heap overflow)" ascii //weight: 1
        $x_2_4 = {48 89 e5 48 83 ec 40 b8 21 00 00 00 b9 01 00 00 00 45 31 c0 41 b9 64 00 00 00 48 89 7d f8 48 89 75 f0 48 89 55 e8 48 8b 7d f8 48 8b 55 f0 48 8b 75 e8 66 41 89 f2 89 c6 48 89 55 e0 89 ca 44 89 c1 4c 8b 5d e0 44 89 4d dc 4d 89 d9 41 0f b7 c2 89 04 24 c7 44 24 08 64 00 00 00}  //weight: 2, accuracy: High
        $x_1_5 = "Firmware/dfu/iBSS.n42ap.RELEASE.dfu" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

