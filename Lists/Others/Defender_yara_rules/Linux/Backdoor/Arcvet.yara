rule Backdoor_Linux_Arcvet_A_2147679457_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Arcvet.gen!A"
        threat_id = "2147679457"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Arcvet"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {b6 b9 af b5 b6 af b0 b2 b8 af b0 b0 b1}  //weight: 2, accuracy: High
        $x_2_2 = {d9 f7 e4 f3 81 d9 e2 e0 f5 81}  //weight: 2, accuracy: High
        $x_1_3 = {e0 f4 e5 e8 f5 de ed ee e6 de f4 f2 e4 f3 de ec e4 f2 f2 e0 e6 e4}  //weight: 1, accuracy: High
        $x_1_4 = {f2 f2 e9 e5 bb b0 88 a4 f2 88 a4 f2 88 a4 f2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

