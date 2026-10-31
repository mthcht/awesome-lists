rule Trojan_Win32_SapphireMiner_AMTB_2147981272_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SapphireMiner!AMTB"
        threat_id = "2147981272"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SapphireMiner"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "icacls \"%SystemRoot%\\System32\\reagentc.exe\" /grant Administrators:F" ascii //weight: 1
        $x_1_2 = "icacls \"%SystemRoot%\\System32\\reagentc.exe\" /deny Everyone:RX" ascii //weight: 1
        $x_1_3 = "reagentc /disable" ascii //weight: 1
        $x_1_4 = "C:\\Users\\marvi\\Downloads\\Sapphire_Miner_Source\\SapphireClient\\x64\\Release\\SapphireClient.pdb" ascii //weight: 1
        $x_1_5 = "cmd.exe /c ping -n 1 -w 1000 8.8.8.8 > nul" ascii //weight: 1
        $x_1_6 = "SOFTWARE\\VMware, Inc.\\VMware Tools" ascii //weight: 1
        $x_1_7 = "SOFTWARE\\Oracle\\VirtualBox Guest Additions" ascii //weight: 1
        $x_1_8 = "schtasks /Delete /TN" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

