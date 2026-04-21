rule Trojan_Win64_PhoenixBreath_A_2147967367_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/PhoenixBreath.A!dha"
        threat_id = "2147967367"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "PhoenixBreath"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "src\\info_collect.rs" ascii //weight: 1
        $x_1_2 = "src\\File_transfer.rs" ascii //weight: 1
        $x_1_3 = "src\\Video_stream.rs" ascii //weight: 1
        $x_1_4 = "-Command(Get-CimInstance -ClassName Win32_ComputerSystem).Domain" ascii //weight: 1
        $x_1_5 = "(Get-CimInstance -ClassName Win32_OperatingSystem).OSArchitecture" ascii //weight: 1
        $x_1_6 = "Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct | Select-Object -ExpandProperty displayName" ascii //weight: 1
        $x_1_7 = "Get-Process | Select-Object Id, ProcessName, StartTime, CPU, Path, WorkingSet | ConvertTo-Json -Compress" ascii //weight: 1
        $x_1_8 = "Get-CimInstance -ClassName Win32_Processor | Select-Object Name, NumberOfCores, NumberOfLogicalProcessors, MaxClockSpeed | ConvertTo-Json" ascii //weight: 1
        $x_1_9 = "Get-CimInstance -ClassName Win32_PhysicalMemory | Select-Object Capacity, Manufacturer | ConvertTo-Json" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

