rule TrojanDropper_Win32_Bizfigy_A_2147707508_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Bizfigy.A"
        threat_id = "2147707508"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Bizfigy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= \"Set obj = CreateObject(\"\"WScript.Shell\"\")" wide //weight: 1
        $x_1_2 = "&= @CRLF & \"obj.Run \"\"\" & @APPDATACOMMONDIR &" wide //weight: 1
        $x_1_3 = ".au3\" , @APPDATACOMMONDIR &" wide //weight: 1
        $x_1_4 = "RUN ( @COMSPEC & \" /c \" & @APPDATACOMMONDIR &" wide //weight: 1
        $x_1_5 = ".vbs\" ) = $CONTENT THEN EXITLOOP" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

