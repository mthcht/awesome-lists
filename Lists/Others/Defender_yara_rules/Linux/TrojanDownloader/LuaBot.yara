rule TrojanDownloader_Linux_LuaBot_A_2147798899_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Linux/LuaBot.A!xp"
        threat_id = "2147798899"
        type = "TrojanDownloader"
        platform = "Linux: Linux platform"
        family = "LuaBot"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {e3 a0 00 02 e3 a0 10 01 e3 a0 20 06 e5 9f 71 40 ef 00 00 00 e3 50 00 00 ba 00 00 4a e1 a0 80 00 e2 4d d0 08 e3 a0 00 05 e5 8d 00 00 e3 a0 00 00 e5 8d 00 04 e1 a0 00 08 e3 a0 10 01 e3 a0 20 14 e1 a0 30 0d e3 a0 40 08 e5 9f 71 08 ef 00 00 00 e2 8d d0 08 e3 50 00 00 1a 00 00 37 e2 4d d0 10 e5 9f 00 f4 e5 8d 00 00 e3 a0 00 00 e5 8d 00 04 e5 8d 00 08 e5 8d 00 0c e1 a0 00 08 e3 a0 10 01 e3 a0 20 19 e1 a0 30 0d e3 a0 40 10 e5 9f 70 c4 ef 00 00 00 e2 8d d0 10 e3 50 00 00 1a 00 00 26 e2 4d d0 10 e5 9f 00 b4 e5 8d 00 00 e5 9f 00 b0 e5 8d 00 04 e3 a0 00 00 e5 8d 00 08 e5 8d 00 0c e1 a0 00 08 e1 a0 10 0d e3 a0 20 10 e5 9f 70 94 ef 00 00 00 e2 8d d0 10 e3 50 00 00 1a 00 00 16 e5 9f 90 84 e3 a0 0c 01 e0 4d d0 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 00 01 1b 00 00 77 b7 00 00 01 23 41 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

