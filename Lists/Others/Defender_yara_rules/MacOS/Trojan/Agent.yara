rule Trojan_MacOS_Agent_A_2147776287_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Agent.A"
        threat_id = "2147776287"
        type = "Trojan"
        platform = "MacOS: "
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "=\"$(ioreg -ad2 -c IOPlatformExpertDevice | xmllint --xpath '//key[.=\"IOPlatformUUID\"]/following-sibling::*[1]/text()' -)\";CONTENT=$(curl --connect-timeout 900 -L \"https://" ascii //weight: 1
        $x_1_2 = ";eval \"$CONTENT\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Agent_F_2147832441_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Agent.F"
        threat_id = "2147832441"
        type = "Trojan"
        platform = "MacOS: "
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {26 26 20 72 6d 20 2d 72 66 20 27 2f 55 73 65 72 73 2f [0-160] 2f 4c 69 62 72 61 72 79 2f 53 61 76 65 64 20 41 70 70 6c 69 63 61 74 69 6f 6e 20 53 74 61 74 65 2f 63 6f 6d 2e 61 70 70 6c 65 2e 54 65 72 6d 69 6e 61 6c 2e 73 61 76 65 64 53 74 61 74 65}  //weight: 2, accuracy: Low
        $x_2_2 = {70 72 69 6e 74 66 20 27 1b 5b 38 3b 31 3b 31 74 27 20 26 26 20 70 72 69 6e 74 66 20 27 1b 5b 32 74 27}  //weight: 2, accuracy: High
        $x_1_3 = {3c 6b 65 79 3e 52 75 6e 41 74 4c 6f 61 64 3c 2f 6b 65 79 3e [0-160] 3c 74 72 75 65 2f 3e [0-160] 3c 6b 65 79 3e 4b 65 65 70 41 6c 69 76 65 3c 2f 6b 65 79 3e}  //weight: 1, accuracy: Low
        $x_1_4 = "killall Terminal" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

