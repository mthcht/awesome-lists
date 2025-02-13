rule VirTool_MSIL_Covent_F_2147756745_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Covent.F"
        threat_id = "2147756745"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Covent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "{\"type\":\"{" wide //weight: 1
        $x_1_2 = "{\"GUID\":" wide //weight: 1
        $x_1_3 = "}\",\"token\":{" wide //weight: 1
        $x_1_4 = "\"EncryptedMessage\":" wide //weight: 1
        $x_1_5 = "\"jitter\":" wide //weight: 1
        $x_1_6 = "\"connectAttempts\":" wide //weight: 1
        $x_1_7 = {4e 61 6d 65 64 50 69 70 65 53 65 72 76 65 72 53 74 72 65 61 6d 00}  //weight: 1, accuracy: High
        $x_1_8 = {4e 61 6d 65 64 50 69 70 65 43 6c 69 65 6e 74 53 74 72 65 61 6d 00}  //weight: 1, accuracy: High
        $x_1_9 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 00}  //weight: 1, accuracy: High
        $x_1_10 = {73 65 74 5f 55 70 73 74 72 65 61 6d 4d 65 73 73 65 6e 67 65 72 00}  //weight: 1, accuracy: High
        $x_1_11 = "GruntTask" ascii //weight: 1
        $x_1_12 = "VXNlci1BZ2VudA==" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (11 of ($x*))
}

rule VirTool_MSIL_Covent_A_2147756747_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Covent.A!!Covent.gen!A"
        threat_id = "2147756747"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Covent"
        severity = "Critical"
        info = "Covent: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "{\"type\":\"{" wide //weight: 1
        $x_1_2 = "{\"GUID\":" wide //weight: 1
        $x_1_3 = "}\",\"token\":{" wide //weight: 1
        $x_1_4 = "\"EncryptedMessage\":" wide //weight: 1
        $x_1_5 = "\"jitter\":" wide //weight: 1
        $x_1_6 = "\"connectAttempts\":" wide //weight: 1
        $x_1_7 = {4e 61 6d 65 64 50 69 70 65 53 65 72 76 65 72 53 74 72 65 61 6d 00}  //weight: 1, accuracy: High
        $x_1_8 = {4e 61 6d 65 64 50 69 70 65 43 6c 69 65 6e 74 53 74 72 65 61 6d 00}  //weight: 1, accuracy: High
        $x_1_9 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 00}  //weight: 1, accuracy: High
        $x_1_10 = {73 65 74 5f 55 70 73 74 72 65 61 6d 4d 65 73 73 65 6e 67 65 72 00}  //weight: 1, accuracy: High
        $x_1_11 = "GruntTask" ascii //weight: 1
        $x_1_12 = "VXNlci1BZ2VudA==" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (11 of ($x*))
}

