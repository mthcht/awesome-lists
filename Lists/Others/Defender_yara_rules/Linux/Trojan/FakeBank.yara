rule Trojan_Linux_FakeBank_B_2147808332_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/FakeBank.B!xp"
        threat_id = "2147808332"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "FakeBank"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "_stringIPNOBank" ascii //weight: 1
        $x_1_2 = "_stringIPBank" ascii //weight: 1
        $x_1_3 = {68 74 74 70 3a 2f 2f [0-16] 2e 69 65 67 6f 2e 6e 65 74 2f 61 70 70 48 6f 6d 65 2f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Linux_FakeBank_GV_2147808847_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/FakeBank.GV!xp"
        threat_id = "2147808847"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "FakeBank"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "_stringIP1" ascii //weight: 1
        $x_1_2 = "_stringIPBank" ascii //weight: 1
        $x_1_3 = {68 74 74 70 3a 2f 2f [0-16] 2e 69 65 67 6f 2e 6e 65 74 2f 61 70 70 48 6f 6d 65 2f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

