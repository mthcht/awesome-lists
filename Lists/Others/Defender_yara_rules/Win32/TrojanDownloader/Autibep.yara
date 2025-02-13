rule TrojanDownloader_Win32_Autibep_C_2147725796_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Autibep.C!bit"
        threat_id = "2147725796"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Autibep"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = " = \"https://inetaccelerator.ru/" wide //weight: 1
        $x_1_2 = "RUN ( @TEMPDIR & \"\\_run_.txt\" , \"\" , @SW_HIDE )" wide //weight: 1
        $x_1_3 = "$RDOWNLOAD = INETGET ( $OUT10 , @TEMPDIR & \"\\_run_.txt\" , 1 , 1 )" wide //weight: 1
        $x_1_4 = "OPT ( \"TrayIconHide\" , 1 )" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_Win32_Autibep_D_2147726235_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Autibep.D!bit"
        threat_id = "2147726235"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Autibep"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$PWD &= $ASPACE [ RANDOM ( 0 , 2 , 1 ) ]" wide //weight: 1
        $x_1_2 = {2e 00 6a 00 70 00 67 00 22 00 0d 00 0a 00 20 00 24 00 50 00 4f 00 48 00 41 00 20 00 3d 00 20 00 40 00 41 00 50 00 50 00 44 00 41 00 54 00 41 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 22 00 20 00 26 00 20 00 22 00 76 00 75 00 76 00 75 00 2e 00 74 00 78 00 74 00 22 00}  //weight: 1, accuracy: High
        $x_1_3 = "OPT ( \"TrayIconHide\" , 1 )" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Autibep_E_2147727011_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Autibep.E!bit"
        threat_id = "2147727011"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Autibep"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = " = DE3264 ( \"aHR0cDovL2lkZWFva2RhLmluZm8vcnVuLXR4dA==" wide //weight: 1
        $x_1_2 = "RUNWAIT ( @TEMPDIR & \"\\run.txt\" , \"\" , @SW_HIDE )" wide //weight: 1
        $x_1_3 = " = INETGET ( $OUT , @TEMPDIR & \"\\run.txt\" , 1 , 1 )" wide //weight: 1
        $x_1_4 = "OPT ( \"TrayIconHide\" , 1 )" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

