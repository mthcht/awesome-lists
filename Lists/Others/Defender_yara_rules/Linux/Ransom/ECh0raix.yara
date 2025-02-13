rule Ransom_Linux_ECh0raix_A_2147827072_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/ECh0raix.A!MTB"
        threat_id = "2147827072"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "ECh0raix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "main.writemessage" ascii //weight: 1
        $x_1_2 = "golang.org/x/crypto/curve25519" ascii //weight: 1
        $x_1_3 = "KeyLogWriter" ascii //weight: 1
        $x_1_4 = "filepath.Walk" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Linux_ECh0raix_B_2147828436_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/ECh0raix.B!MTB"
        threat_id = "2147828436"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "ECh0raix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "main.decryptTestFile" ascii //weight: 1
        $x_1_2 = "filepath.Walk" ascii //weight: 1
        $x_1_3 = "canWriteRecord" ascii //weight: 1
        $x_1_4 = "dirtyLocked" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Linux_ECh0raix_C_2147848245_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/ECh0raix.C!MTB"
        threat_id = "2147848245"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "ECh0raix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {08 10 3b 25 08 40 35 25 08 18 3b 25 08 48 35 25 08 20 3b 25 08 50 35 25 08 28 3b 25 08 58 35 25 08 30 3b 25 08 60 35 25 08 38 3b 25 08 68 35 25 08 40 3b 25 08 70 35 25 08 48 3b 25 08 78 35 25 08 50 3b 25 08 80 35 25 08 58 3b 25 08 88 35 25 08 60 3b 25 08 90 35 25 08 68 3b 25 08 98 35 25}  //weight: 1, accuracy: High
        $x_1_2 = {34 25 08 50 3a 25 08 80 34 25 08 58 3a 25 08 88}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

