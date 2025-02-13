rule Backdoor_Win32_Mulcss_A_2147642526_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Mulcss.A"
        threat_id = "2147642526"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Mulcss"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {80 3c 24 0a 74 21 80 3c 24 ac 75 0e 80 7c 24 01 10 72 07 80 7c 24 01 1f}  //weight: 1, accuracy: High
        $x_1_2 = "%SystemRoot%\\System32\\svchost.exe -k" ascii //weight: 1
        $x_1_3 = {bc e0 cc fd b5 c4 b6 cb bf da ba c5 ce aa 30 21}  //weight: 1, accuracy: High
        $x_1_4 = "sc config UI0Detect start= disabled" ascii //weight: 1
        $x_1_5 = {00 64 65 6c 20 25 30 00}  //weight: 1, accuracy: High
        $x_1_6 = "SOFTWARE\\ODBC\\SQLLevel" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

