rule Trojan_Win32_Emulga_A_2147600188_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emulga.A"
        threat_id = "2147600188"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emulga"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Windows Explorer cdrom optimizer" ascii //weight: 1
        $x_1_2 = "DllCanUnloadNow" ascii //weight: 1
        $x_1_3 = "DllGetClassObject" ascii //weight: 1
        $x_1_4 = "GetDomen" ascii //weight: 1
        $x_1_5 = "MakeItTopWWW" ascii //weight: 1
        $x_1_6 = "Replace_urlW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

