rule TrojanDropper_AndroidOS_Penguin_A_2147830599_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:AndroidOS/Penguin.A!xp"
        threat_id = "2147830599"
        type = "TrojanDropper"
        platform = "AndroidOS: Android operating system"
        family = "Penguin"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {03 68 31 1c 9b 69 98 47 06 1e 07 d1 2b 68 28 1c 5b 6c 98 47 26 60 66 60 30 1c}  //weight: 1, accuracy: High
        $x_1_2 = {39 1c 01 9a 08 9b ff f7 af ff 07 1e 07 d1 2b 68 28 1c 5b 6c 98 47 27 60 67 60 38 1c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

