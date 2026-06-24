rule Trojan_MacOS_Gaslight_DA_2147972259_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Gaslight.DA!MTB"
        threat_id = "2147972259"
        type = "Trojan"
        platform = "MacOS: "
        family = "Gaslight"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {61 6b 36 69 2f 58 44 72 33 37 4f 75 42 73 39 72 33 59 41 30 47 54 4d 36 6a 6e 67 63 59 74 69 6e 6c 55 66 79 4e 78 7a 4f 7a 71 39 56 45 4d 61 43 56 35 65 70 48 0a 62 46 36 76 72 6c 38 6d 42 6b 67 6d 33 49 31 53 2b 78 76 34 73 31 36 51 51 48 53 4e 36 43 46 7a 69 76 64 34 2b 33 69 31 44 67 33 2b 73 54 57 77 49 46 4a 67 74 69 79 2b 68 43 6b 53 55 74 44 4c 0a 35 56 71 6a 4b 41 32 77 56 49 54 64 62 76 30 54 49 68 36 57 35 45 50 64 44 6c 2f 35 6f 77 35 44 4a 67 3d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Gaslight_DB_2147972260_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Gaslight.DB!MTB"
        threat_id = "2147972260"
        type = "Trojan"
        platform = "MacOS: "
        family = "Gaslight"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "killed by OOM killer" ascii //weight: 1
        $x_1_2 = "not working on iPhone" ascii //weight: 1
        $x_1_3 = "/issuesFailed to create issue" ascii //weight: 1
        $x_1_4 = "/commentsFailed to post comment" ascii //weight: 1
        $x_1_5 = "upload shell" ascii //weight: 1
        $x_1_6 = "Unknown commandaddremove-cshpublic/fonts" ascii //weight: 1
        $x_1_7 = "[+] File uploaded to:" ascii //weight: 1
        $x_1_8 = "[-] Failed to upload file:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

