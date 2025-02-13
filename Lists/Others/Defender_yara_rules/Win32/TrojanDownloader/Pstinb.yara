rule TrojanDownloader_Win32_Pstinb_A_2147707904_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Pstinb.A"
        threat_id = "2147707904"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Pstinb"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DIM $ROOT = @STARTUPDIR" wide //weight: 1
        $x_1_2 = "DIM $INITLINK = \"http://pastebin.com/" wide //weight: 1
        $x_1_3 = "DIM $INIT_URL = BINARYTOSTRING ( INETREAD ( $INITLINK ) )" wide //weight: 1
        $x_1_4 = "INETGET ( $INIT_URL , $ROOT & \"\\\" & $INIT_FILENAME , 1 )" wide //weight: 1
        $x_1_5 = "IF FILEEXISTS ( $ROOT & \"\\\" & $INIT_FILENAME ) THEN SHELLEXECUTE ( $ROOT & \"\\\" & $INIT_FILENAME" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Pstinb_B_2147729973_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Pstinb.B!bit"
        threat_id = "2147729973"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Pstinb"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 72 6c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 2c 20 68 74 74 70 73 3a 2f 2f 70 61 73 74 65 62 69 6e 2e 63 6f 6d 2f 72 61 77 2f 32 53 54 54 59 66 74 7a 2c 20 25 50 72 6f 67 72 61 6d 44 61 74 61 25 5c [0-32] 2e 76 62 73}  //weight: 1, accuracy: Low
        $x_1_2 = {52 75 6e 20 25 50 72 6f 67 72 61 6d 44 61 74 61 25 5c [0-32] 2e 76 62 73}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

