rule Trojan_Win32_Rtkit_A_2147740622_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rtkit.A!MTB"
        threat_id = "2147740622"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rtkit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PsRemoveLoadImageNotifyRoutine" ascii //weight: 1
        $x_1_2 = "\\DosDevices\\A_DeviceName" wide //weight: 1
        $x_1_3 = "\\Device\\A_DeviceName" wide //weight: 1
        $x_1_4 = "d:\\p\\loser\\a\\a\\objfre_wxp_x86\\i386\\A.pdb" ascii //weight: 1
        $x_1_5 = "MmMapLockedPagesSpecifyCache" ascii //weight: 1
        $x_1_6 = "HalMakeBeep" ascii //weight: 1
        $x_1_7 = "ntoskrnl.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

