rule Trojan_Win32_SystemHijack_B_2147599221_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SystemHijack.B!dll"
        threat_id = "2147599221"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SystemHijack"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "26"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Afx:400000:0:10011:0:0" ascii //weight: 1
        $x_10_2 = "C:\\WINDOWS\\ojl111.dll" ascii //weight: 10
        $x_10_3 = "mynew.dll" ascii //weight: 10
        $x_1_4 = "IMEINPUTS.EXE" ascii //weight: 1
        $x_1_5 = "AutoPatch.exe" ascii //weight: 1
        $x_1_6 = "soul.exe" ascii //weight: 1
        $x_1_7 = "WriteProcessMemory" ascii //weight: 1
        $x_1_8 = "URLDownloadToFileA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SystemHijack_B_2147599221_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SystemHijack.B!dll"
        threat_id = "2147599221"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SystemHijack"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "26"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Afx:400000:0:10011:0:0" ascii //weight: 1
        $x_10_2 = "C:\\WINDOWS\\ojl111.dll" ascii //weight: 10
        $x_10_3 = "Souldll.dll" ascii //weight: 10
        $x_1_4 = "daqu=%s&xiaoqu=%s&user=%s&pass=%s&ckpass=%s&renwu=%s&level=%d&gold=%d&stone=%d&cpname=%s" ascii //weight: 1
        $x_1_5 = "http://www.88vcd.com/htm/china/myb/send.asp?daqu=%s&xiaoqu=%s&user=%s&pass=%s&ckpass=%s&renwu=%s&level=%d&gold=%d&stone=%d&cpname" ascii //weight: 1
        $x_1_6 = "Send_ck1" ascii //weight: 1
        $x_1_7 = "BankBG" ascii //weight: 1
        $x_1_8 = "InternetOpenUrlA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

