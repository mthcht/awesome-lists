rule Trojan_Win32_Zacom_C_2147711207_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zacom.C"
        threat_id = "2147711207"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zacom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "REG ADD HKCU\\software\\microsoft\\windows\\currentversion\\run /t REG_EXPAND_SZ /v msnetbridge /f /d \"%s\"" ascii //weight: 1
        $x_1_2 = "C:\\Users\\SoundOF\\Desktop\\aveo\\Release\\aveo.pdb" ascii //weight: 1
        $x_1_3 = "index.php?id=35471&1=%s&9=%s" ascii //weight: 1
        $x_1_4 = "index.php?id=35469&1=%s&9=%s" ascii //weight: 1
        $x_1_5 = "cmd /c copy \"%s\" \"%s\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

