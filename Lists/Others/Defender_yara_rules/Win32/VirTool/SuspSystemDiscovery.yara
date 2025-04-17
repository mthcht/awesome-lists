rule VirTool_Win32_SuspSystemDiscovery_BS_2147939263_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/SuspSystemDiscovery.BS"
        threat_id = "2147939263"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspSystemDiscovery"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = " & net accounts & " ascii //weight: 1
        $x_1_2 = " & net session & " ascii //weight: 1
        $x_1_3 = " & qwinsta & " ascii //weight: 1
        $x_1_4 = " & net config server & " ascii //weight: 1
        $x_1_5 = " & wmic bios & " ascii //weight: 1
        $x_1_6 = " & wmic qfe get hotfixid & " ascii //weight: 1
        $x_1_7 = " & wmic startup & " ascii //weight: 1
        $x_1_8 = " & wmic os & " ascii //weight: 1
        $x_1_9 = " & wmic useraccount get /all & " ascii //weight: 1
        $x_1_10 = " & wmic share get /all & " ascii //weight: 1
        $x_1_11 = " & wmic service brief & " ascii //weight: 1
        $x_1_12 = " & wmic path win32_logicaldisk get caption,filesystem,freespace,size,volumename & " ascii //weight: 1
        $x_1_13 = " & powershell -executionpolicy bypass -command \"get-eventlog security -instanceid" ascii //weight: 1
        $x_1_14 = " & dnscmd . /enumzones & " ascii //weight: 1
        $x_1_15 = "nul & netsh firewall show state & " ascii //weight: 1
        $x_1_16 = "nul & ipconfig /all & " ascii //weight: 1
        $x_1_17 = "nul & route print & " ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

