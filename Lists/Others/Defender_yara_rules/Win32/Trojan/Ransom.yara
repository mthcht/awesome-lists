rule Trojan_Win32_Ransom_CA_2147805529_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ransom.CA!MTB"
        threat_id = "2147805529"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ransom"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 04 f5 b4 65 40 00 0f b7 d7 66 0f be 0c 10 b8 ff 00 00 00 66 33 cf 66 23 c8 0f b6 04 f5 b0 65 40 00 66 33 c8 47 66 89 0c 53 66 3b 3c f5 b2 65 40 00 72 cc}  //weight: 1, accuracy: High
        $x_1_2 = {fe c3 0f b6 f3 8a 14 3e 02 fa 0f b6 cf 8a 04 39 88 04 3e 88 14 39 0f b6 0c 3e 0f b6 c2 03 c8 81 e1 ff 00 00 00 8a 04 39 8b 4c 24 10 30 04 29 45 3b 6c 24 14 72 ca}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ransom_CD_2147808316_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ransom.CD!MTB"
        threat_id = "2147808316"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ransom"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 1c 01 33 1c 11 75 0a 83 c1 04 78 f3}  //weight: 1, accuracy: High
        $x_1_2 = {8a 5c 31 06 f6 c3 80 75 e1 32 1c 11 f6 c3 80 75 d9 80 e3 df 75 d0 49 75 e7}  //weight: 1, accuracy: High
        $x_1_3 = "Ransomware Demo" ascii //weight: 1
        $x_1_4 = "Decrypt *.encry to original file extension." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

