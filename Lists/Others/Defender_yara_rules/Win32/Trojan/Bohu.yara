rule Trojan_Win32_Bohu_A_2147641681_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bohu.A!Installer"
        threat_id = "2147641681"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bohu"
        severity = "Critical"
        info = "Installer: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%%\\nethome32.dll RundllInstall NetHomeIDE" ascii //weight: 1
        $x_1_2 = "%%\\netplayone\\MyIEData" ascii //weight: 1
        $x_1_3 = "dns 61.158.160.197,61.158.160.206" ascii //weight: 1
        $x_1_4 = "msfsg.exe md5 -s spass.dll -d spass.dll" ascii //weight: 1
        $x_1_5 = "\\baidu\\dsetup.exe install" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

