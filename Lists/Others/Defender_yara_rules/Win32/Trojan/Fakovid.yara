rule Trojan_Win32_Fakovid_PA_2147752336_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fakovid.PA!MSR"
        threat_id = "2147752336"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fakovid"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "covid-19 informer.pdb" ascii //weight: 1
        $x_1_2 = "covid-19 informer.exe" ascii //weight: 1
        $x_1_3 = "http://tiny.cc/" wide //weight: 1
        $x_1_4 = "C:\\\\HiddenFolder\\\\" wide //weight: 1
        $x_1_5 = "setup" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fakovid_PB_2147753172_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fakovid.PB!MSR"
        threat_id = "2147753172"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fakovid"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {64 61 6f 6c 6e 77 6f 64 3d 74 72 6f 70 78 65 26 [0-36] 3d 64 69 3f 63 75 2f 30 2f 75 2f 6d 6f 63 2e 65 6c 67 6f 6f 67 2e 65 76 69 72 64 2f 2f 3a 73 70 74 74 68}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

