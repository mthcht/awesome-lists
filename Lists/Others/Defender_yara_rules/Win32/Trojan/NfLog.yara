rule Trojan_Win32_NfLog_A_2147642622_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NfLog.A"
        threat_id = "2147642622"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NfLog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "NfLog/TTip.asp" ascii //weight: 1
        $x_1_2 = "/NfCommand.asp" ascii //weight: 1
        $x_1_3 = "NfStart" ascii //weight: 1
        $x_1_4 = "c:\\myfile.dat" ascii //weight: 1
        $x_1_5 = "NfcoreOk" ascii //weight: 1
        $x_1_6 = "&dtime=" ascii //weight: 1
        $x_1_7 = "?ClientId=" ascii //weight: 1
        $x_1_8 = "MyTmpFile.Dat" ascii //weight: 1
        $x_1_9 = "?par=comedata" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule Trojan_Win32_NfLog_A_2147644875_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NfLog.A!dll"
        threat_id = "2147644875"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NfLog"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {50 72 6f 63 47 6f 00 00 4e 66 4c 6f 67 2f 4e 66 69 6c 65 2e 61 73 70 00}  //weight: 1, accuracy: High
        $x_1_2 = "SvcHostDLL.exe" ascii //weight: 1
        $x_1_3 = "System32\\svchost.exe -k netsvcs" ascii //weight: 1
        $x_1_4 = "RegSetValueEx(ServiceDll)" ascii //weight: 1
        $x_1_5 = {4e 66 63 6f 72 65 4f 6b 00}  //weight: 1, accuracy: High
        $x_1_6 = {53 76 63 57 69 6e 65 74 2e 65 78 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

