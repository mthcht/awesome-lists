rule Trojan_MSIL_ScreenLock_MB_2147763245_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ScreenLock.MB!MTB"
        threat_id = "2147763245"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ScreenLock"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Please Enter Updated Product Key" ascii //weight: 1
        $x_1_2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_3 = "shutdown -a -t 0'h" ascii //weight: 1
        $x_1_4 = "http://themediafox.com/hipop2/locker/api/sendkey" ascii //weight: 1
        $x_1_5 = "http://themediafox.com/hipop2/locker/api/keystroke" ascii //weight: 1
        $x_1_6 = "disable_ad" ascii //weight: 1
        $x_1_7 = "taskkill /f /im taskmgr.exe" ascii //weight: 1
        $x_1_8 = "Release\\Win Act.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

