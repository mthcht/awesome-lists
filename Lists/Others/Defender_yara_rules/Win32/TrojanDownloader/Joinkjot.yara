rule TrojanDownloader_Win32_Joinkjot_A_2147690863_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Joinkjot.gen!A"
        threat_id = "2147690863"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Joinkjot"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {81 38 4d 49 4e 45}  //weight: 1, accuracy: High
        $x_1_2 = {81 fb 41 50 33 32}  //weight: 1, accuracy: High
        $x_1_3 = {81 ff 5b bc 4a 6a}  //weight: 1, accuracy: High
        $x_1_4 = "GetModuleFileName(GetModuleHandle(0))" ascii //weight: 1
        $x_1_5 = "UserName/ComputerName" ascii //weight: 1
        $x_1_6 = "WMI_Processes" ascii //weight: 1
        $x_1_7 = "Registry-->PhysicalDrive" ascii //weight: 1
        $x_1_8 = "AM-U0_0.0.4" ascii //weight: 1
        $x_2_9 = "0=%s&1=%lu&2=%s&3=%s&4=%s&5=%s&6=%s&7=%s&8=%s" wide //weight: 2
        $x_1_10 = "0=%s&1=%s" wide //weight: 1
        $x_1_11 = "home-off-d5f0ac" wide //weight: 1
        $x_1_12 = "dell-d3e62f7e26" wide //weight: 1
        $x_1_13 = "kakaprou-6405da" wide //weight: 1
        $x_1_14 = "] - Serial:" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

