rule Trojan_Win32_VulnDriver_VGZ_2147966257_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VulnDriver.VGZ!MTB"
        threat_id = "2147966257"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VulnDriver"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HandleIoctl: IOCTL CALLED: 0x%x" ascii //weight: 1
        $x_1_2 = "HandleIoctl: PsLookupProcessByProcessId failed with status 0x%x" ascii //weight: 1
        $x_1_3 = "HandleIoctl: UntrustFile failed with status 0x%x" ascii //weight: 1
        $x_1_4 = "HandleIoctl: TerminateProcessByPID failed with status 0x%x" ascii //weight: 1
        $x_1_5 = "Driver unloaded." ascii //weight: 1
        $x_1_6 = "HandleCreate: Device opened." ascii //weight: 1
        $x_1_7 = "Driver loaded." ascii //weight: 1
        $x_1_8 = "IofCompleteRequest" ascii //weight: 1
        $x_1_9 = "IoCreateDevice" ascii //weight: 1
        $x_1_10 = "IoCreateSymbolicLink" ascii //weight: 1
        $x_1_11 = "IoDeleteDevice" ascii //weight: 1
        $x_1_12 = "IoDeleteSymbolicLink" ascii //weight: 1
        $x_1_13 = "\\DosDevices\\KMHLPDRV" wide //weight: 1
        $x_1_14 = "\\Device\\KMHLPDRV" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

