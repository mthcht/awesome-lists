rule Trojan_AndroidOS_Browbot_R_2147899122_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Browbot.R"
        threat_id = "2147899122"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Browbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {68 61 70 70 79 61 70 69 73 2e 63 6f 6d 2f 64 61 74 61 5f ?? ?? 2f}  //weight: 2, accuracy: Low
        $x_2_2 = {62 75 74 74 6f 6e 52 65 73 75 6d 65 5f ?? ?? 00}  //weight: 2, accuracy: Low
        $x_2_3 = {62 75 74 74 6f 6e 43 68 65 63 6b 50 65 72 6d 69 73 73 69 6f 6e 5f ?? ?? 00}  //weight: 2, accuracy: Low
        $x_2_4 = {73 65 6e 64 65 72 70 68 6f 6e 65 5f ?? ?? 00}  //weight: 2, accuracy: Low
        $x_2_5 = {53 6d 73 52 65 63 65 69 76 65 72 41 63 74 69 76 69 74 79 5f ?? ?? 00}  //weight: 2, accuracy: Low
        $x_2_6 = {73 6f 75 72 63 65 7a 5f ?? ?? 00}  //weight: 2, accuracy: Low
        $x_2_7 = "apinetcom.com/data" ascii //weight: 2
        $x_2_8 = {64 61 74 61 5f ?? ?? 2f 69 6e 73 74 61 6c 6c 5f ?? ?? 00}  //weight: 2, accuracy: Low
        $x_2_9 = "a8p.net/tqfXDn" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_AndroidOS_Browbot_Y_2147928919_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Browbot.Y"
        threat_id = "2147928919"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Browbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {73 65 6e 64 65 72 70 68 6f 6e 65 5f ?? ?? 00}  //weight: 2, accuracy: Low
        $x_2_2 = {63 72 65 64 65 6e 74 69 61 6c 73 4c 61 75 6e 63 68 65 72 5f ?? ?? 00}  //weight: 2, accuracy: Low
        $x_2_3 = {64 61 74 61 5f ?? ?? 2f 69 6e 64 65 78 5f ?? ?? 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

