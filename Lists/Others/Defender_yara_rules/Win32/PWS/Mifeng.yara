rule PWS_Win32_Mifeng_A_2147596391_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Mifeng.gen!A"
        threat_id = "2147596391"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Mifeng"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Shdocvw_tlb@TCppWebBrowser" ascii //weight: 1
        $x_1_2 = "fb:C++HOOK" ascii //weight: 1
        $x_1_3 = "websamba.com" ascii //weight: 1
        $x_1_4 = "CreateToolhelp32Snapshot" ascii //weight: 1
        $x_1_5 = "Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_6 = "net stop \"Internet Connection Firewall" ascii //weight: 1
        $x_1_7 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 1
        $x_1_8 = "multipart/alternative" ascii //weight: 1
        $x_2_9 = {68 74 74 70 3a 2f 2f 62 65 66 6f 72 65 2e ?? ?? 2e 73 74}  //weight: 2, accuracy: Low
        $x_2_10 = "/ryabcdefg/mf6db/index.asp?eve=" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((8 of ($x_1_*))) or
            ((1 of ($x_2_*) and 6 of ($x_1_*))) or
            ((2 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

