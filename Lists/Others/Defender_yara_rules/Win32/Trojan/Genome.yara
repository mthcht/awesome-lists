rule Trojan_Win32_Genome_AA_2147634351_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Genome.AA"
        threat_id = "2147634351"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Genome"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "tj5.nncj.net/5f5tlmadmin/co5tu5mnt.asp" ascii //weight: 1
        $x_1_2 = "_deleteme.bat" ascii //weight: 1
        $x_1_3 = {c4 be c2 ed b8 a8 d6 fa b2 e9 d5 d2 c6 f7}  //weight: 1, accuracy: High
        $x_1_4 = {d6 c7 d6 c7 d7 a8 b0 e6 d7 a5 b0 fc b9 a4 be df}  //weight: 1, accuracy: High
        $x_1_5 = {d6 c7 d6 c7 d7 a5 b0 fc b9 a4 be df 2e 65 78 65}  //weight: 1, accuracy: High
        $x_1_6 = {cf c2 d4 d8 d5 df bc e0 ca d3 c6 f7}  //weight: 1, accuracy: High
        $x_1_7 = {b8 eb d7 d3 b9 a4 d7 f7 ca d2 b2 e9 b6 be b9 a4 be df 2e 65 78 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_Genome_C_2147637029_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Genome.C"
        threat_id = "2147637029"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Genome"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "D:\\PROGRA~1\\WinRAR\\dodo.vbs" ascii //weight: 1
        $x_1_2 = {25 73 5c 25 73 00 00 00 2e 65 78 65 00 00 00 00 61 64 6d 69 6e 6c 6f 67 2e 65 78 65 00 00 00 00 52 61 76 4d 6f 6e 44 2e 65 78 65}  //weight: 1, accuracy: High
        $x_1_3 = {54 52 55 45 29 0d 0d 0a 09 09 09 09 09 09 09 09 20 57 73 63 72 69 70 74 2e 53 6c 65 65 70 20 33 30 30 30 30 30 0d 0a}  //weight: 1, accuracy: High
        $x_1_4 = {5c cc da d1 b6 c8 ed bc fe 00 00 00 cc da d1 b6 54 54 00 00 b0 c1 d3 ce e4 af c0 c0 c6 f7 00 00 ca c0 bd e7 d6 ae b4 b0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

