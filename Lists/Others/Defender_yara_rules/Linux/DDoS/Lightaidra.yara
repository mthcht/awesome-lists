rule DDoS_Linux_Lightaidra_2147717463_0
{
    meta:
        author = "defender2yara"
        detection_name = "DDoS:Linux/Lightaidra"
        threat_id = "2147717463"
        type = "DDoS"
        platform = "Linux: Linux platform"
        family = "Lightaidra"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "irc_" ascii //weight: 1
        $x_1_2 = "scan" ascii //weight: 1
        $x_1_3 = "flood" ascii //weight: 1
        $x_1_4 = "attack" ascii //weight: 1
        $x_1_5 = "fin.ack" ascii //weight: 1
        $x_1_6 = "password" ascii //weight: 1
        $x_1_7 = "root" ascii //weight: 1
        $x_1_8 = "shell" ascii //weight: 1
        $x_1_9 = "ftpget" ascii //weight: 1
        $x_1_10 = "admin1234" ascii //weight: 1
        $x_1_11 = "XA1bac0MX" ascii //weight: 1
        $x_1_12 = "dreambox" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (11 of ($x*))
}

rule DDoS_Linux_Lightaidra_2147717463_1
{
    meta:
        author = "defender2yara"
        detection_name = "DDoS:Linux/Lightaidra"
        threat_id = "2147717463"
        type = "DDoS"
        platform = "Linux: Linux platform"
        family = "Lightaidra"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {00 4b 49 4c 4c 41 54 54 4b 00}  //weight: 4, accuracy: High
        $x_4_2 = {00 53 43 41 4e 4e 45 52 20 4f 4e 20 7c 20 4f 46 46 00}  //weight: 4, accuracy: High
        $x_2_3 = {00 61 73 73 77 6f 72 64 00}  //weight: 2, accuracy: High
        $x_2_4 = {00 6e 63 6f 72 72 65 63 74 00}  //weight: 2, accuracy: High
        $x_2_5 = {00 4d 79 20 49 50 3a 20 25 73 00}  //weight: 2, accuracy: High
        $x_2_6 = {00 41 74 74 65 6d 70 74 20 2d 20 25 73 3a 25 73 3a 25 73 00}  //weight: 2, accuracy: High
        $x_2_7 = {00 64 72 65 61 6d 62 6f 78 00}  //weight: 2, accuracy: High
        $x_2_8 = {00 76 69 7a 78 76 00}  //weight: 2, accuracy: High
        $x_2_9 = {00 63 69 73 63 6f 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_2_*))) or
            ((1 of ($x_4_*) and 3 of ($x_2_*))) or
            ((2 of ($x_4_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule DDoS_Linux_Lightaidra_YA_2147741057_0
{
    meta:
        author = "defender2yara"
        detection_name = "DDoS:Linux/Lightaidra.YA!MTB"
        threat_id = "2147741057"
        type = "DDoS"
        platform = "Linux: Linux platform"
        family = "Lightaidra"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ftpget -v -u anonymous -p anonymous -P 21" ascii //weight: 1
        $x_1_2 = "BOAT CRACKED:" ascii //weight: 1
        $x_1_3 = "Server_Botport" ascii //weight: 1
        $x_1_4 = "HackerScan2" ascii //weight: 1
        $x_1_5 = "botkiller" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule DDoS_Linux_Lightaidra_B_2147762564_0
{
    meta:
        author = "defender2yara"
        detection_name = "DDoS:Linux/Lightaidra.B!MTB"
        threat_id = "2147762564"
        type = "DDoS"
        platform = "Linux: Linux platform"
        family = "Lightaidra"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "://ytest.co/bins.sh" ascii //weight: 1
        $x_1_2 = "tftp -g ytest.co -r tftp.sh" ascii //weight: 1
        $x_1_3 = {6e 61 6d 65 73 65 72 76 65 72 20 38 2e 38 2e 38 2e 38 ?? ?? 6e 61 6d 65 73 65 72 76 65 72 20 38 2e 38 2e 34 2e 34}  //weight: 1, accuracy: Low
        $x_1_4 = "BOT JOINED" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule DDoS_Linux_Lightaidra_C_2147763061_0
{
    meta:
        author = "defender2yara"
        detection_name = "DDoS:Linux/Lightaidra.C!MTB"
        threat_id = "2147763061"
        type = "DDoS"
        platform = "Linux: Linux platform"
        family = "Lightaidra"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {51 68 bd f2 04 08 68 4c f9 04 08 e8 ee fc ff ff 58 5a 68 4c f9 04 08 68 4c f9 04 08 e8 dd fc ff ff 5d 58 68 59 fa 04 08 68 59 fa 04 08 e8 cc fc ff ff 5e 5f 68 54 f9 04 08 68 54 f9 04 08 e8 bb fc ff ff 59 5b 68 48 fb 04 08 68 5b f9 04 08 e8 aa fc ff ff 58 5a 68 bd f2 04 08 68 5b f9 04 08 e8 99 fc ff ff 5d 58 68 bd f2 04 08 68 59 fa 04 08 e8 88 fc ff ff 5e 5f 68 61 f9 04 08 68 61 f9 04 08 e8 77 fc ff ff}  //weight: 2, accuracy: High
        $x_1_2 = {8b 54 24 1c 83 c4 10 8b 02 8d 8c 24 9c 04 00 00 c7 00 4a 6f 6b 65 c7 40 04 72 45 70 69 c7 40 08 63 6e 65 73 66 c7 40 0c 73 00 8d 94 24 1c 04 00 00 8d 84 24 1c 05 00 00 89 4c 24 08 89 44 24 04 89 14 24 eb 2c}  //weight: 1, accuracy: High
        $x_1_3 = "greeth" ascii //weight: 1
        $x_1_4 = "greip" ascii //weight: 1
        $x_1_5 = "xmas" ascii //weight: 1
        $x_1_6 = "stomp" ascii //weight: 1
        $x_1_7 = "udpbypass" ascii //weight: 1
        $x_1_8 = "tcpfrag" ascii //weight: 1
        $x_1_9 = "tcpraw" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule DDoS_Linux_Lightaidra_D_2147763294_0
{
    meta:
        author = "defender2yara"
        detection_name = "DDoS:Linux/Lightaidra.D!MTB"
        threat_id = "2147763294"
        type = "DDoS"
        platform = "Linux: Linux platform"
        family = "Lightaidra"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {1c f2 ff eb 78 0d 9f e5 ac 1c 9f e5 6c 2f 9f e5 18 f2 ff eb 68 0d 9f e5 98 1c 9f e5 4c 2d 9f e5 14 f2 ff eb 90 1c 9f e5 54 0d 9f e5 01 20 a0 e1 10 f2 ff eb 50 1f 9f e5 44 0d 9f e5 01 20 a0 e1 0c f2 ff eb 38 0d 9f e5 6c 1c 9f e5 f0 2e 9f e5 08 f2 ff eb 28 0d 9f e5 5c 1c 9f e5 4c 2e 9f e5 04 f2 ff eb 18 0d 9f e5 4c 1c 9f e5 4c 2c 9f e5 00 f2 ff eb 08 0d 9f e5 3c 1c 9f e5 84 2c 9f e5}  //weight: 2, accuracy: High
        $x_1_2 = "P@55w0rd!" ascii //weight: 1
        $x_1_3 = "tsunami" ascii //weight: 1
        $x_1_4 = "root1234" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

