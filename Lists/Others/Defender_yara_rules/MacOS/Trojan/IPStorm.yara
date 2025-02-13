rule Trojan_MacOS_IPStorm_A_2147765116_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/IPStorm.A!MTB"
        threat_id = "2147765116"
        type = "Trojan"
        platform = "MacOS: "
        family = "IPStorm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "storm/malware-guard" ascii //weight: 1
        $x_1_2 = {73 74 6f 72 6d 2f 70 6f 77 65 72 73 68 65 6c 6c 2e [0-16] 2e 53 74 61 72 74 50 72 6f 63 65 73 73}  //weight: 1, accuracy: Low
        $x_1_3 = "storm/backshell.StartServer" ascii //weight: 1
        $x_1_4 = {66 69 6c 65 74 72 61 6e 73 66 65 72 2e [0-32] 2e 45 6e 73 75 72 65 41 75 74 6f 53 74 61 72 74}  //weight: 1, accuracy: Low
        $x_1_5 = "storm/commander/web_app/router" ascii //weight: 1
        $x_1_6 = "avbypass" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

