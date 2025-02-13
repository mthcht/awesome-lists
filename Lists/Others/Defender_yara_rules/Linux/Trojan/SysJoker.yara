rule Trojan_Linux_SysJoker_A_2147810734_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/SysJoker.A!MTB"
        threat_id = "2147810734"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "SysJoker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 74 70 73 3a 2f 2f [0-24] 2f 75 63 3f 65 78 70 6f 72 74 3d 64 6f 77 6e 6c 6f 61 64 26 69 64 3d 31 57 36 34 50 51 51 78 72 77 59 33 58 6a 42 6e 76 5f 51 41 65 42 51 75 2d 65 50 72 35 33 37 65 75}  //weight: 1, accuracy: Low
        $x_1_2 = {74 74 70 73 3a 2f 2f [0-24] 2f 75 63 3f 65 78 70 6f 72 74 3d 64 6f 77 6e 6c 6f 61 64 26 69 64 3d 31 2d 4e 56 74 79 34 59 58 30 64 50 48 64 78 6b 67 4d 72 62 64 43 6c 64 51 43 70 43 61 45 2d 48 6e}  //weight: 1, accuracy: Low
        $x_2_3 = {63 72 6f 6e 74 61 62 20 2d 6c 20 7c 20 65 67 72 65 70 20 2d 76 20 [0-3] 5e 28 23 7c 24 29 [0-3] 20 7c 20 67 72 65 70 20 2d 65}  //weight: 2, accuracy: Low
        $x_2_4 = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDkfNl+Se7jm7sGSrSSUpV3HUl3vEwuh+xn4qBY6aRFL91x0HIgcH2AM2rOlLdoV8v1vtG1oPt9QpC1jSxShnFw8evGrYnqaou7gLsY5J2B06eq5UW7+OXgb77WNbU90vyUbZAucfzy0eF1HqtBNbkXiQ6SSbquuvFPUepqUEjUSQIDAQAB" ascii //weight: 2
        $x_2_5 = "/api/attach" ascii //weight: 2
        $x_1_6 = {48 89 c7 e8 ?? ?? 00 00 c7 45 ec 00 00 00 00 48 8d 85 f8 fc ff ff ba b5 ea 45 00 be 28 27 68 00 48 89 c7 e8 ?? ?? 00 00 48 8d 85 f0 fc ff ff ba 30 27 68 00 be ac e9 45 00 48 89 c7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

