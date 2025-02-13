rule Backdoor_AndroidOS_Moavt_A_2147826655_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:AndroidOS/Moavt.A!xp"
        threat_id = "2147826655"
        type = "Backdoor"
        platform = "AndroidOS: Android operating system"
        family = "Moavt"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 74 74 70 33 30 32 65 6e 64 00 4b 48}  //weight: 1, accuracy: High
        $x_1_2 = {69 50 69 6e 46 61 6e 00 4b 53 65 72 76 65 72 43 6c 6f 73}  //weight: 1, accuracy: High
        $x_1_3 = {6c 65 70 68 6f 6e 79 2f 63 61 72 72 69 65 72 73 00 61 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

