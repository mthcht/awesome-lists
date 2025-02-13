rule Worm_Win32_Bizfigy_A_2147707509_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Bizfigy.A"
        threat_id = "2147707509"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Bizfigy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ProcessExists(\"avgui.exe\") Then Sleep(" wide //weight: 1
        $x_1_2 = ".vbs\", 'Set objShell = WScript.CreateObject(\"WScript.Shell\")' & @CRLF)" wide //weight: 1
        $x_1_3 = ".vbs\", 'Set lnk = objShell.CreateShortcut(" wide //weight: 1
        $x_1_4 = ".vbs\", 'lnk.TargetPath =" wide //weight: 1
        $x_1_5 = "0xC81000005356578365F800E8500000003EFFFFFF3F3435363738393A3B3C3" wide //weight: 1
        $x_1_6 = "ControlSetText (\"[CLASS:tSkMainForm]" wide //weight: 1
        $x_1_7 = "DllCall(\"ntdll.dll\", \"none\", \"ZwSetInformationProcess" wide //weight: 1
        $x_1_8 = "ShellExecute(\"ipconfig.exe\", \"/release *\", \"\", \"\", @SW_HIDE)" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

