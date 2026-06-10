rule Backdoor_AndroidOS_Keenadu_A_2147971269_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:AndroidOS/Keenadu.A!MSR"
        threat_id = "2147971269"
        type = "Backdoor"
        platform = "AndroidOS: Android operating system"
        family = "Keenadu"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com.ak.test.Main" ascii //weight: 1
        $x_1_2 = {a0 87 8c 24 65 54 15 72 6a 62 c5 09 10 27 e2 bc f1 c3 73 c3 fd 4c 11 27 ae 1e 80 b5 7b 67 c6 23 ba a5 cc da 68 28 b4 96 09 cd 26 c3 a1 6a 1f 93 ba 92 61 5f 23 65 2b ff 18 c0 48 1b db 38 80 6b 79 e6 be d5 23 59 8f 8a 07 b7 7a ca 39 fb c8 c2 58 40 c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

