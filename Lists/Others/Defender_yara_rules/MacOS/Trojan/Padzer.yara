rule Trojan_MacOS_Padzer_A_2147756726_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Padzer.A!MTB"
        threat_id = "2147756726"
        type = "Trojan"
        platform = "MacOS: "
        family = "Padzer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2f 55 73 65 72 73 2f 75 73 65 72 2f 64 65 76 [0-21] 2f 6e 73 6c 61 75 6e 63 68 64 2f 6e 73 6c 61 75 6e 63 68 64}  //weight: 1, accuracy: Low
        $x_2_2 = {2f 74 6d 70 2f 00 77 62 00 68 65 61 64 20 2d 63 20 00 20 2f 64 65 76 2f 7a 65 72 6f 20 3e 3e 20 00 63 68 6d 6f 64 20 2b 78 20 00 73 6c 65 65 70 20 36 30 00 26 00 0a 23 21 2f 62 69 6e 2f 62 61 73 68}  //weight: 2, accuracy: High
        $x_2_3 = "if pgrep \"Activity Monitor\" > /dev/null;then killall" ascii //weight: 2
        $x_1_4 = "/Applications/Final\\ Cut\\ Pro.app/Contents/MacOS/.Final\\ Cut\\ Pro" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MacOS_Padzer_B_2147842817_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Padzer.B!MTB"
        threat_id = "2147842817"
        type = "Trojan"
        platform = "MacOS: "
        family = "Padzer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/tmp/i2pd" ascii //weight: 1
        $x_1_2 = {fe ff 74 2d 48 85 c9 75 14 48 8d 45 d8 48 8d 4d d7 48 89 4b 30 48 89 4b 28 48 89 43 38 44 88 31 48 8b 53 28 48 8b 4b 30 48 ff c1 48 89 4b 30 eb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

