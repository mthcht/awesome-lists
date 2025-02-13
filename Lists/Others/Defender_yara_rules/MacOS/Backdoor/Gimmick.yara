rule Backdoor_MacOS_Gimmick_A_2147815683_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MacOS/Gimmick.A!MTB"
        threat_id = "2147815683"
        type = "Backdoor"
        platform = "MacOS: "
        family = "Gimmick"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {fe c9 48 81 fa c8 00 00 00 75 ?? 48 c7 c3 fe ff ff ff 4c 8d 25 aa 88 04 00 4c 8d 35 e9 f7 02 00 4c 8d bd ac fb ff ff 41 bd 02 00 00 00 c6 85 ae fb ff ff 00 66 c7 85 ac fb ff ff 00 00 0f be 94 1d b2 fb ff ff 0f be 8c 1d b3 fb ff ff 4c 89 ff 4c 89 f6 31 c0 e8 ?? ?? ?? ?? 4c 89 ff 31 f6 ba 10 00 00 00 e8 ?? ?? ?? ?? 41 88 04 24 4c 01 eb 49 ff c4 48 83 fb 1e 72 ?? 48 8d bd e0 fb ff ff e8 ?? ?? ?? ?? 8b 3d 85 83 04 00}  //weight: 5, accuracy: Low
        $x_5_2 = {29 05 00 91 3f 21 03 f1 21 ?? ?? ?? 14 00 80 d2 b5 74 23 10 1f 20 03 d5 f6 83 00 91 93 64 18 50 1f 20 03 d5 ff 7b 00 39 ff 3b 00 79 c8 02 14 8b 09 01 80 39 08 05 80 39 e9 23 00 a9 e0 73 00 91 e1 03 13 aa ad ?? ?? ?? e0 73 00 91 01 00 80 d2 02 02 80 52 c1 ?? ?? ?? a0 16 00 38 88 0a 00 91 9f 7a 00 f1 f4 03 08 aa e3 ?? ?? ?? e0 43 01 91 3f ?? ?? ?? 68 4c 23 30}  //weight: 5, accuracy: Low
        $x_1_3 = "CredsQueue" ascii //weight: 1
        $x_1_4 = "DriveUploadQueue" ascii //weight: 1
        $x_1_5 = {74 74 70 73 3a 2f 2f [0-37] 2f 75 70 6c 6f 61 64 2f 64 72 69 76 65 2f 76 33 2f 66 69 6c 65 73 3f 61 6c 74 3d 6a 73 6f 6e 26 75 70 6c 6f 61 64 54 79 70 65 3d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 3 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

