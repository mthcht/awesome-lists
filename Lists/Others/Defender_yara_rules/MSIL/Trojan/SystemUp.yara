rule Trojan_MSIL_SystemUp_A_2147829321_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SystemUp.A!dha"
        threat_id = "2147829321"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SystemUp"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {43 4c 52 64 6c 6c 2e 64 6c 6c 00 47 65 74 43 75 72 72 65 6e 74 49 6e 74 65 72 6e 61 6c 5f 52 65 70 6f 72 74 52 6f 6c 6c 62 61 63 6b 45 76 65 6e 74}  //weight: 1, accuracy: High
        $x_1_2 = {48 61 6e 64 6c 65 53 68 65 6c 6c 00 50 72 6f 67 72 61 6d}  //weight: 1, accuracy: High
        $x_1_3 = "SystemUp.Properties" ascii //weight: 1
        $x_1_4 = "BEASDZXXXMEL" ascii //weight: 1
        $x_1_5 = "YEPTRUPTASKAMELANAZ" ascii //weight: 1
        $x_1_6 = "StarShell" ascii //weight: 1
        $x_1_7 = "ShellWriteLine" ascii //weight: 1
        $x_1_8 = "ProcessShell" ascii //weight: 1
        $x_1_9 = "SystemUp.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

