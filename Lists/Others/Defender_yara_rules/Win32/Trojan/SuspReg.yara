rule Trojan_Win32_SuspReg_D_2147954145_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspReg.D"
        threat_id = "2147954145"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspReg"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd.exe /c systeminfo" ascii //weight: 1
        $x_1_2 = "AppData\\Local\\Temp\\temp.ini" ascii //weight: 1
        $x_1_3 = "tasklist" ascii //weight: 1
        $x_1_4 = "makecab" ascii //weight: 1
        $x_1_5 = "temp.cab" ascii //weight: 1
        $n_1_6 = "69802c98-2cg2-4a17-98w0-3a9220ad0157" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_SuspReg_D_2147954145_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspReg.D"
        threat_id = "2147954145"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspReg"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "reg.exe query" ascii //weight: 1
        $x_1_2 = "HKLM\\HARDWARE\\DEVICEMAP\\Scsi\\Scsi" ascii //weight: 1
        $x_1_3 = "VMWARE" ascii //weight: 1
        $x_1_4 = "QEMU" ascii //weight: 1
        $x_1_5 = "HKEY_LOCAL_MACHINE\\Hardware\\Description\\System" ascii //weight: 1
        $x_1_6 = "SystemBiosVersion" wide //weight: 1
        $n_1_7 = "69802c98-2cf2-4a17-98w0-3a9220ad0157" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (3 of ($x*))
}

