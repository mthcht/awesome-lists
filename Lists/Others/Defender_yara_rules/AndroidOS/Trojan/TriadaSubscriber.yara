rule Trojan_AndroidOS_TriadaSubscriber_A_2147789528_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/TriadaSubscriber.A"
        threat_id = "2147789528"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "TriadaSubscriber"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DTEUFg==" ascii //weight: 1
        $x_1_2 = "Cy0HFggBBkg=" ascii //weight: 1
        $x_1_3 = "Gy0CHBMSQwAAJ1YoJR8P" ascii //weight: 1
        $x_1_4 = {21 51 12 02 48 03 05 02 e1 03 03 04 dd 03 03 0f 48 04 05 02 e0 04 04 04 d5 44 f0 00 b6 43 8d 33 4f 03 05 02 12 12 35 12 13 00 48 03 05 02 d5 33 ff 00 d8 04 02 ff 48 04 05 04 d5 44 ff 00 b7 43 8d 33 4f 03 05 02 d8 02 02 01}  //weight: 1, accuracy: High
        $x_1_5 = {35 12 92 00 d8 03 02 01 48 02 08 02 d5 22 ff 00 33 13 20 00 62 08 2b 01 e2 01 02 02 49 08 08 01 6e 20 35 04 80 00 62 08 2b 01 dd 01 02 03 e0 01 01 04 49 08 08 01 6e 20 35 04 80 00 1a 08 8f 02 71 10 59 02 08 00 0c 08 6e 20 36 04 80 00 28 6b d8 04 03 01 48 03 08 03 d5 33 ff 00 33 14 29 00 62 08 2b 01 e2 01 02 02 49 08 08 01 6e 20 35 04 80 00 62 08 2b 01 dd 01 02 03 e0 01 01 04 d5 32 f0 00 e2 02 02 04 b6 21 49 08 08 01 6e 20 35 04 80 00 62 08 2b 01 dd 01 03 0f e0 01 01 02 49 08 08 01 6e 20 35 04 80 00 1a 08 8e 02 28 ca}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

