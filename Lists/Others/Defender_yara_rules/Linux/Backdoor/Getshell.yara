rule Backdoor_Linux_Getshell_D_2147836796_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Getshell.D!MTB"
        threat_id = "2147836796"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Getshell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/tmp/socks5.sh" ascii //weight: 1
        $x_1_2 = "cat <(echo '@reboot echo socks5_backconnect666" ascii //weight: 1
        $x_1_3 = "/socks5_backconnect666" ascii //weight: 1
        $x_1_4 = "crontab -l 2>" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Getshell_E_2147850529_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Getshell.E!MTB"
        threat_id = "2147850529"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Getshell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {14 59 5b 5e 52 68 02 00 11 5c 6a 10 51 50 89 e1 6a 66 58 cd 80 d1 e3 b0 66 cd 80 57 43 b0 66 89 51 04 cd 80 93 89 df 53 51 6a 00 6a 10 e8 10 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {10 00 00 31 db 53 89 e6 6a 40 b7 0a 53 56 53 89 e1 86 fb 66 ff 01 6a 66 58 cd 80 81 3e}  //weight: 1, accuracy: High
        $x_1_3 = {85 c0 79 44 4e 74 68 68 a2 00 00 00 58 6a 00 6a 05 89 e3 31 c9 cd 80 85 c0 79 bd eb 52 53 51 6a 00 6a 10 e8 10 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Backdoor_Linux_Getshell_F_2147850530_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Getshell.F!MTB"
        threat_id = "2147850530"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Getshell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 00 00 07 00 00 00 00 10 00 00 31 db 53 43 53 6a 02 6a 66 58}  //weight: 1, accuracy: High
        $x_1_2 = {cd 80 66 81 7f 02 8f ec 75 f1 5b 6a 02 59 b0 3f cd 80 49 79 f9}  //weight: 1, accuracy: High
        $x_1_3 = {6a 3c 58 6a 01 5f 0f 05 6a 10 5a e8 10 00 00 00 88 e4 bb 86 70 51 4f cb b8 f1 d9 e5 9e 56 2f 0c 5e 48 31 c0 48 ff c0 0f 05 eb d5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Backdoor_Linux_Getshell_G_2147850531_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Getshell.G!MTB"
        threat_id = "2147850531"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Getshell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 02 00 03 00 01 00 00 00 54 80 04 08 34 00 00 00 00 00 00 00 00 00 00 00 34 00 20 00 01 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00 00 80 04 08 00 80 04 08 dd 01 00 00 66 03 00 00 07 00 00 00 00 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Getshell_H_2147850532_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Getshell.H!MTB"
        threat_id = "2147850532"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Getshell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {02 00 03 00 01 00 00 00 54 80 04 08 34 00 00 00 00 00 00 00 00 00 00 00 34 00 20 00 01 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00 00 80 04 08 00 80 04 08 b3 00 00 00 12 01 00 00 07 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Getshell_J_2147889516_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Getshell.J!MTB"
        threat_id = "2147889516"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Getshell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6a 3b 58 99 48 bb 2f 62 69 6e 2f 73 68 00 53 48 89 e7 68 2d 63 00 00 48 89 e6 52 e8 e9 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Getshell_AB_2147903255_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Getshell.AB!MTB"
        threat_id = "2147903255"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Getshell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 48 89 e5 48 83 ec 30 c7 45 fc 29 23 00 00 ba 00 00 00 00 be 01 00 00 00 bf 02 00 00 00 e8 d4 fe ff ff 89 45 f8 66 c7 45 e0 02 00 8b 45 fc 0f b7 c0 89 c7 e8 6e fe ff ff 66 89 45 e2 48 8d 05 37 0e 00 00 48 89 c7 e8 8b fe ff ff 89 45 e4 48 8d 4d e0 8b 45 f8 ba 10 00 00 00 48 89 ce 89 c7 e8 82 fe ff ff 8b 45 f8 be 00 00 00 00 89 c7 e8 43 fe ff ff 8b 45 f8 be 01 00 00 00 89 c7 e8 34 fe ff ff 8b 45 f8 be 02 00 00 00 89 c7 e8 25 fe ff ff 48 8d 05 ee 0d 00 00 48 89 45 d0 48 c7 45 d8 00 00 00 00 48 8d 45 d0 ba 00 00 00 00 48 89 c6 48 8d 05 cf 0d 00 00 48 89 c7 e8 07 fe ff ff b8 00 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

