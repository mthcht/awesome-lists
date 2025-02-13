rule Trojan_Linux_Dakkatoni_Az_2147761880_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Dakkatoni.Az!MTB"
        threat_id = "2147761880"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Dakkatoni"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "/drupal/_u.jpg|sh" ascii //weight: 1
        $x_1_2 = {73 6c 65 65 70 20 33 3b 20 69 66 20 21 20 70 73 20 61 75 78 20 7c 20 67 72 65 70 20 2d 76 20 27 67 72 65 70 27 20 7c 20 67 72 65 70 20 2d 71 20 27 2f 73 62 69 6e 2f 61 74 6e 64 27 3b 20 74 68 65 6e 20 77 67 65 74 20 2d 4f 20 2d 20 ?? ?? ?? ?? 3a 2f 2f [0-3] 2e [0-3] 2e [0-3] 2e [0-3] 2f 64 72 75 70 61 6c 2f 5f 75 2e 73 68 7c 73 68}  //weight: 1, accuracy: Low
        $x_1_3 = "/tmp/.mine" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Linux_Dakkatoni_P_2147809145_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Dakkatoni.P!MTB"
        threat_id = "2147809145"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Dakkatoni"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/tmp/.httpslog" ascii //weight: 1
        $x_1_2 = "k.conectionapis.com" ascii //weight: 1
        $x_1_3 = "/etc/cron.d/httpsd" ascii //weight: 1
        $x_1_4 = "*/6 * * * root " ascii //weight: 1
        $x_1_5 = "/tmp/.httpspid" ascii //weight: 1
        $x_1_6 = "key=%s&host_name=%s&cpu_count=%d&os_type=%s&core_count=%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Linux_Dakkatoni_B_2147900992_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Dakkatoni.B!MTB"
        threat_id = "2147900992"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Dakkatoni"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {62 cc b0 72 a5 23 bd 13 d7 14 35 b9 67 45 8e 61 eb f1 9d 0e 8f 21 69 e6 78 01 ba 7e e6 33 eb 0a 85 c3 dc 81 3c 4d 42 1e 84 b1 e7 ab}  //weight: 1, accuracy: High
        $x_1_2 = {88 dd c7 3b 19 69 78 86 ce be 1c 97 63 a8 f2 33 f7 46 25 d3 81 fe 16 4f 00 8d 47 fc b5 1f f9 7a 66 f2 8a 5a 4b 63 4d b4 e5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

