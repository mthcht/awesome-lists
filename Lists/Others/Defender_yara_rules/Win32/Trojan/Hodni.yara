rule Trojan_Win32_Hodni_A_2147707553_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Hodni.A"
        threat_id = "2147707553"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Hodni"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "TCPSEND ( $MAIN_SOCKET , \"NEW_HOUDINI\" & $SPLIT & STRINGUPPER ( $CLIENT_INFO ) & @CRLF )" wide //weight: 1
        $x_1_2 = "TCPSEND ( $FILE_MANAGER_SOCKET , \"FILE_MANAGER_THUMB\" & @CRLF )" wide //weight: 1
        $x_1_3 = "FILECREATESHORTCUT ( \"\" , $SZDRIVE & $SZDIR & $SZFNAME & \".LNK\"" wide //weight: 1
        $x_1_4 = "$WEBCAM_THREAD = SHELLEXECUTE ( @SCRIPTFULLPATH , \"WEBCAM\" )" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

