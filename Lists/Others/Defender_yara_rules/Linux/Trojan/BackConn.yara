rule Trojan_Linux_BackConn_A_2147745250_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/BackConn.A!MTB"
        threat_id = "2147745250"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "BackConn"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6a 0a 5e 31 db f7 e3 53 43 53 6a 02 b0 66 89 e1 cd 80 97 5b 68 9b 5e ec a0 68 02 00 1f a7 89 e1 6a 66 58 50 51 57 89 e1 43 cd 80 85 c0 79 19 4e 74 3d 68 a2 00 00 00 58 6a 00 6a 05 89 e3 31 c9 cd 80 85 c0 79 bd eb 27}  //weight: 1, accuracy: High
        $x_1_2 = {b2 07 b9 00 10 00 00 89 e3 c1 eb 0c c1 e3 0c b0 7d cd 80 85 c0 78 10 5b 89 e1 99 b6 0c b0 03 cd 80 85 c0 78 02 ff e1 b8 01 00 00 00 bb 01 00 00 00 cd 80}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Linux_BackConn_B_2147745258_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/BackConn.B!MTB"
        threat_id = "2147745258"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "BackConn"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/etc/init.d/update-notifier" ascii //weight: 1
        $x_1_2 = "etc/rc2.d/S01update-notifier" ascii //weight: 1
        $x_2_3 = {48 be 58 2d 41 63 63 65 73 73 43 c6 44 37 10 00 48 89 32 48 8b 34 24 f2 ae 48 8d 42 0a 48 89 c7 48 f7 d1 48 ff c9 f3 a4 c6 44 1a 0a 00 48 8b 4c 24 28 48 8d 5c 24 38 48 8d 74 24 58 49 89 d8 ba 02 00 00 00 0f 11 5c 24 38 48 8d 3d aa 43 13 00 0f 11 5c 24 48 e8 95 fb ff ff 85 c0 0f 84 e7 fe ff ff 48 83 7c 24 40 00 75 07}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

