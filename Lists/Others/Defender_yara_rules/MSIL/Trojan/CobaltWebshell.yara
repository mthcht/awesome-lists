rule Trojan_MSIL_CobaltWebshell_AA_2147795880_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CobaltWebshell.AA!MTB"
        threat_id = "2147795880"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CobaltWebshell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WriteUTF8ResourceString" ascii //weight: 1
        $x_1_2 = {43 6f 6e 76 65 72 74 00 46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67}  //weight: 1, accuracy: High
        $x_1_3 = {67 65 74 5f 54 6f 74 61 6c 4d 69 6c 6c 69 73 65 63 6f 6e 64 73 00 54 6f 49 6e 74 33 32 00 48 74 74 70 52 65 73 70 6f 6e 73 65 00 67 65 74 5f 52 65 73 70 6f 6e 73 65 00 73 65 74 5f 53 74 61 74 75 73 00 45 6e 64 00 50 72 6f 63 65 73 73 53 74 61 72 74 49 6e 66 6f}  //weight: 1, accuracy: High
        $x_1_4 = {73 65 74 5f 55 73 65 53 68 65 6c 6c 45 78 65 63 75 74 65 00 50 72 6f 63 65 73 73 00 53 74 61 72 74}  //weight: 1, accuracy: High
        $x_1_5 = "POST" wide //weight: 1
        $x_1_6 = "sessionid" wide //weight: 1
        $x_1_7 = "404 File Not Found" wide //weight: 1
        $x_1_8 = "apikeyd" wide //weight: 1
        $x_1_9 = "cmd.exe" wide //weight: 1
        $x_1_10 = "ZZzzZzZz" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CobaltWebshell_AC_2147797104_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CobaltWebshell.AC!MTB"
        threat_id = "2147797104"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CobaltWebshell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 00 54 65 6d 70 6c 61 74 65 43 6f 6e 74 72 6f 6c 00 73 65 74 5f 41 70 70 52 65 6c 61 74 69 76 65 56 69 72 74 75 61 6c 50 61 74 68}  //weight: 3, accuracy: High
        $x_3_2 = {52 65 61 64 53 74 72 69 6e 67 52 65 73 6f 75 72 63 65 00 53 74 72 69 6e 67 00 47 65 74 57 72 61 70 70 65 64 46 69 6c 65 44 65 70 65 6e 64 65 6e 63 69 65 73 00 43 6f 6e 74 72 6f 6c}  //weight: 3, accuracy: High
        $x_3_3 = {49 52 65 71 75 69 72 65 73 53 65 73 73 69 6f 6e 53 74 61 74 65 00 49 48 74 74 70 48 61 6e 64 6c 65 72}  //weight: 3, accuracy: High
        $x_3_4 = "App_Web_" ascii //weight: 3
        $x_3_5 = "iismeta" ascii //weight: 3
        $x_3_6 = ".aspx" ascii //weight: 3
        $x_3_7 = "AddWrappedFileDependencies" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

