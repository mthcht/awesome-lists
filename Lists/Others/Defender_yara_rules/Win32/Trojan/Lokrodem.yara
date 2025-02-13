rule Trojan_Win32_Lokrodem_A_2147598769_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokrodem.A"
        threat_id = "2147598769"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokrodem"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "*.exe;*.dll;*.sys" ascii //weight: 1
        $x_1_2 = "Randomizing size: Appended" ascii //weight: 1
        $x_1_3 = "ferro.tmp" ascii //weight: 1
        $x_1_4 = "c:\\autoexec.bat" ascii //weight: 1
        $x_1_5 = "KillRunedCopies -" ascii //weight: 1
        $x_1_6 = "Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_7 = "file hidden" ascii //weight: 1
        $x_1_8 = "Processing redirect stopped" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule Trojan_Win32_Lokrodem_A_2147598770_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokrodem.A"
        threat_id = "2147598770"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokrodem"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<script language=\"JavaScript" ascii //weight: 1
        $x_1_2 = "Exception writeredirect" ascii //weight: 1
        $x_1_3 = "about:blank" ascii //weight: 1
        $x_1_4 = "\">window.location=\"" ascii //weight: 1
        $x_1_5 = "SetSite - begin" ascii //weight: 1
        $x_1_6 = "DllCanUnloadNow" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

