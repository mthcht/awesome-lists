rule TrojanDownloader_Win32_Sabity_A_2147725170_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Sabity.A!bit"
        threat_id = "2147725170"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Sabity"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "IF INETGET ( " wide //weight: 1
        $x_1_2 = "RUNWAIT ( @TEMPDIR & \"\\7za.exe\" & \" x \"\"\" &" wide //weight: 1
        $x_1_3 = "_CRYPT_STARTUP ( )" wide //weight: 1
        $x_1_4 = "BINARYTOSTRING ( _CRYPT_DECRYPTDATA ( $SDATA , \"sec\" , $CALG_RC4 ) )" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

