rule TrojanSpy_Linux_XKeyLogger_A_2147825986_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Linux/XKeyLogger.A!xp"
        threat_id = "2147825986"
        type = "TrojanSpy"
        platform = "Linux: Linux platform"
        family = "XKeyLogger"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {31 ed 5e 89 e1 83 e4 f8 50 54 52 68 fc 92 04 08 68 24 86 04 08 51 56 68 e0 88 04 08}  //weight: 1, accuracy: High
        $x_1_2 = {83 c4 10 83 7d 08 03 75 2d 83 c4 f4 8b 45 0c 83 c0 08 8b 10 52 8b 45 0c 83 c0 04 8b 10 52 68 66 93 04 08 6a 7f 8d 85 48 ff ff ff 50}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

