rule TrojanProxy_Win32_Small_DD_2147597135_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Small.DD"
        threat_id = "2147597135"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "107"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "mail.mindspring.com" ascii //weight: 1
        $x_1_2 = "Hardware\\Description\\System\\CentralProcessor\\0" ascii //weight: 1
        $x_1_3 = "lsas.exe" ascii //weight: 1
        $x_1_4 = "csrss.dll" ascii //weight: 1
        $x_1_5 = "#32770" ascii //weight: 1
        $x_1_6 = "SysListView32" ascii //weight: 1
        $x_1_7 = "Shellspl" ascii //weight: 1
        $x_1_8 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_100_9 = {b8 01 00 00 00 85 c0 0f 84 8e 00 00 00 6a 00 68 ?? ?? 00 10 ff 15 ?? ?? 00 10 89 45 fc 83 7d fc 00 74 3e 6a 00 68 ?? ?? 00 10 6a 00 8b 4d fc 51 ff 15 ?? ?? 00 10 89 45 f4 6a 00 68 ?? ?? 00 10 6a 00 8b 55 f4 52 ff 15 ?? ?? 00 10 89 45 f4 83 7d f4 00 74 0c 8b 45 f4 50 e8 ?? ?? ff ff 83 c4 04 68 ?? ?? 00 10 68 ?? ?? 00 10 e8 ?? ?? ff ff 83 c4 08 85 c0 75 17 68 ?? ?? 00 10 68 ?? ?? 00 10 68 ?? ?? 00 10 e8 ?? ?? ff ff 83 c4 0c 6a 32 ff 15 ?? ?? 00 10 e9 65 ff ff ff b8 01 00 00 00 8b e5 5d c2 04 00}  //weight: 100, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 7 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanProxy_Win32_Small_DE_2147602528_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Small.DE"
        threat_id = "2147602528"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "xgf!&t!&my!)&mv!0!&mv*" ascii //weight: 1
        $x_1_2 = "]Sfhjtusz]Nbdijof]Tztufn]DvssfouDpouspmTfu]Tfswjdft]&t" ascii //weight: 1
        $x_1_3 = "%%%%%JEIMES%%%%%" ascii //weight: 1
        $x_1_4 = {6d 65 73 60 70 71 01 01 5d 5d 2f 5d 74 69 65 01 01 01 01 01 5d 5d 2f 5d 48 6d 70 63 62 6d 5d 74}  //weight: 1, accuracy: High
        $x_1_5 = {5d 65 73 6a 77 66 73 74 5d 6f 65 6a 74 2f 74 7a 74 01}  //weight: 1, accuracy: High
        $x_1_6 = {6c 64 70 65 66 2f 74 7a 74 01}  //weight: 1, accuracy: High
        $x_1_7 = {64 3b 5d 6f 75 6d 65 73 2f 74 7a 74 01}  //weight: 1, accuracy: High
        $x_1_8 = "mes`me &my" ascii //weight: 1
        $x_1_9 = {64 3b 5d 67 78 65 73 77 2f 74 7a 74 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanProxy_Win32_Small_DV_2147603108_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Small.DV"
        threat_id = "2147603108"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%SystemRoot%\\System32\\svchost.exe -k netsvcs" ascii //weight: 1
        $x_1_2 = "AdjustTokenPrivileges" ascii //weight: 1
        $x_1_3 = "SeShutdownPrivilege" ascii //weight: 1
        $x_1_4 = "EnumProcessModules" ascii //weight: 1
        $x_1_5 = "ReadProcessMemory" ascii //weight: 1
        $x_1_6 = "OpenProcessToken" ascii //weight: 1
        $x_1_7 = "SeDebugPrivilege" ascii //weight: 1
        $x_1_8 = "UuidCreate" ascii //weight: 1
        $x_1_9 = "\\usbpda.dll" ascii //weight: 1
        $x_1_10 = "\\usbpdaup.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

