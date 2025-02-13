rule Trojan_MacOS_SamScissors_A_2147843749_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/SamScissors.A"
        threat_id = "2147843749"
        type = "Trojan"
        platform = "MacOS: "
        family = "SamScissors"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "UpdateAgent" ascii //weight: 1
        $x_1_2 = ".main_storage" ascii //weight: 1
        $x_1_3 = {55 4f 54 4a 5a 52 2d 13 14 1e 15 0d 09 5a 34 2e 5a 4b 4a 54 4a 41 5a 2d 13 14 4c 4e 41 5a 02 4c 4e 53 5a 3b 0a 0a 16 1f 2d 1f 18 31 13 0e 55 4f 49 4d 54 49 4c 5a 52 31 32 2e 37 36 56 5a 16 13 11 1f 5a 3d 1f 19 11 15 53 5a 39 12 08 15 17 1f 55 4b 4a 42 54 4a 54 4f 49 4f 43 54 4b 48 42 5a 29 1b 1c 1b 08 13 55 4f 49 4d 54 49 4c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_SamScissors_B_2147844041_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/SamScissors.B"
        threat_id = "2147844041"
        type = "Trojan"
        platform = "MacOS: "
        family = "SamScissors"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "payload2-55554944839216049d683075bc3f5a8628778bb8" ascii //weight: 2
        $x_1_2 = "3cx_auth_id=%s;3cx_auth_token_content=%s;__tutma=true" ascii //weight: 1
        $x_1_3 = "https://sbmsa.wiki/blog/_insert" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

