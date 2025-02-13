rule Trojan_MacOS_DaclsRAT_A_2147754804_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/DaclsRAT.A!dha"
        threat_id = "2147754804"
        type = "Trojan"
        platform = "MacOS: "
        family = "DaclsRAT"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {55 48 89 e5 41 57 41 56 41 54 53 48 81 ec 30 04 00 00 49 89 f7 49 89 fe 48 8b 05 09 31 08 00 48 8b 00 48 89 45 d8 48 8d 35 e3 56 08 00 ba 0c 00 00 00 e8 a9 bb ff ff 85 c0 0f 84 a6 01 00 00 8b 1d cf 56 08 00 81 fb f8 3f 00 00 0f 87 94 01 00 00 89 1d c5 56 08 00 4c 8b 25 c2 56 08 00 be 00 40 00 00 4c 89 e7 e8 63 ff 06 00}  //weight: 2, accuracy: High
        $x_1_2 = {48 89 e5 41 57 41 56 53 50 49 89 d7 48 89 f3 49 89 fe e8 14 05 07 00 85 c0 74 15 b9 ff ff ff ff 0f 4f c8 89 c8 48 83 c4 08 5b 41 5e 41 5f 5d c3}  //weight: 1, accuracy: High
        $x_1_3 = "/Library/LaunchDaemons/com.aex-loop.agent.plist" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

