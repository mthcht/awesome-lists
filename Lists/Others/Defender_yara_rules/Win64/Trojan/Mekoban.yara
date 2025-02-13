rule Trojan_Win64_Mekoban_DA_2147918474_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Mekoban.DA!MTB"
        threat_id = "2147918474"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Mekoban"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "31"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "C:\\Users\\Musquitao" ascii //weight: 20
        $x_1_2 = "LOAD_EXE\\x64\\Release\\LOAD_EXE.pdb" ascii //weight: 1
        $x_10_3 = "Adobe Download Manager" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Mekoban_DAA_2147919032_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Mekoban.DAA!MTB"
        threat_id = "2147919032"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Mekoban"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 00 3a 00 5c 00 55 00 73 00 65 00 72 00 73 00 5c 00 4d 00 75 00 73 00 71 00 75 00 69 00 74 00 61 00 6f 00 5c 00 44 00 65 00 73 00 6b 00 74 00 6f 00 70 00 5c 00 42 00 52 00 5f 00 32 00 30 00 32 00 33 00 5c 00 4c 00 4f 00 41 00 44 00 43 00 50 00 50 00 32 00 30 00 32 00 34 00 5c 00 [0-30] 5c 00 78 00 36 00 34 00 5c 00 52 00 65 00 6c 00 65 00 61 00 73 00 65 00 5c 00 [0-30] 2e 00 70 00 64 00 62 00}  //weight: 1, accuracy: Low
        $x_1_2 = {43 3a 5c 55 73 65 72 73 5c 4d 75 73 71 75 69 74 61 6f 5c 44 65 73 6b 74 6f 70 5c 42 52 5f 32 30 32 33 5c 4c 4f 41 44 43 50 50 32 30 32 34 5c [0-30] 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c [0-30] 2e 70 64 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

