rule Trojan_Win32_Wuke_A_2147574670_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Wuke.A!sys"
        threat_id = "2147574670"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Wuke"
        severity = "Critical"
        info = "sys: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "D:\\Woker\\GetTureOp\\objfre_wnet_x86\\i386\\SysDrver.pdb" ascii //weight: 10
        $x_10_2 = "D:\\Woker\\DRIVER\\objfre_wnet_x86\\i386\\SysDrver.pdb" ascii //weight: 10
        $x_1_3 = "\\DosDevices\\SysDrver" wide //weight: 1
        $x_1_4 = "\\Device\\MediaDrver" wide //weight: 1
        $x_1_5 = "\\DosDevices\\MediaDrver" wide //weight: 1
        $x_1_6 = "\\Device\\SysDrver" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

