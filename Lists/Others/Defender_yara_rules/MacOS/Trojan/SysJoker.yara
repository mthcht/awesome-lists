rule Trojan_MacOS_SysJoker_A_2147812157_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/SysJoker.A!MTB"
        threat_id = "2147812157"
        type = "Trojan"
        platform = "MacOS: "
        family = "SysJoker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 74 70 73 3a 2f 2f [0-24] 2f 75 63 3f 65 78 70 6f 72 74 3d 64 6f 77 6e 6c 6f 61 64 26 69 64 3d 31 57 36 34 50 51 51 78 72 77 59 33 58 6a 42 6e 76 5f 51 41 65 42 51 75 2d 65 50 72 35 33 37 65 75}  //weight: 1, accuracy: Low
        $x_1_2 = "/Users/mac/Desktop/test/test/json.hpp" ascii //weight: 1
        $x_1_3 = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDkfNl+Se7jm7sGSrSSUpV3HUl3vEwuh+xn4qBY6aRFL91x0HIgcH2AM2rOlLdoV8v1vtG1oPt9QpC1jSxShnFw8evGrYnqaou7gLsY5J2B06eq5UW7+OXgb77WNbU90vyUbZAucfzy0eF1HqtBNbkXiQ6SSbquuvFPUepqUEjUSQIDAQAB" ascii //weight: 1
        $x_1_4 = "/api/attach" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

