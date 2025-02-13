rule Worm_Win32_Respup_A_2147611359_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Respup.A"
        threat_id = "2147611359"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Respup"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Worm/Bronco.VAX" ascii //weight: 1
        $x_1_2 = "MSVBVM60.DLL" ascii //weight: 1
        $x_1_3 = "C:\\Program Files\\Microsoft Visual Studio\\VB98\\VB6.OLB" ascii //weight: 1
        $x_1_4 = "C:\\PROGRA~1\\MICROS~4\\VB98\\PUPSRE.vbp" wide //weight: 1
        $x_1_5 = "Scripting.FileSystemObject" wide //weight: 1
        $x_1_6 = "getdrive" wide //weight: 1
        $x_1_7 = "PUPSRE.exe" wide //weight: 1
        $x_1_8 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_9 = "C:\\WINDOWS\\inf\\ssvhost.exe" wide //weight: 1
        $x_1_10 = "My Pictures.exe" wide //weight: 1
        $x_1_11 = "My Documents.exe" wide //weight: 1
        $x_1_12 = "Drive F:\\ infected" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

