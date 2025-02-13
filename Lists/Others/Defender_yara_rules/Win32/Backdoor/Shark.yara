rule Backdoor_Win32_Shark_E_2147601296_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Shark.E"
        threat_id = "2147601296"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Shark"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\sharK 3\\Injector\\Project1.vbp" wide //weight: 1
        $x_1_2 = "modUserlandUnhooking" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Shark_2147605695_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Shark"
        threat_id = "2147605695"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Shark"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "*\\AC:\\DOKUME~1\\SNIPER~1\\Desktop\\sharK\\SERVER~1\\Project1.vbp" wide //weight: 1
        $x_1_2 = "Select * from FirewallProduct" wide //weight: 1
        $x_1_3 = "Select * from AntiVirusProduct" wide //weight: 1
        $x_1_4 = "C:\\update_svr_di.exe" wide //weight: 1
        $x_1_5 = "CSocketMaster" wide //weight: 1
        $x_1_6 = "VMWareService.exe" wide //weight: 1
        $x_1_7 = "PANIC_KILL" wide //weight: 1
        $x_1_8 = "\\regssvr2.bat" wide //weight: 1
        $x_1_9 = "LISTPLUGINS" wide //weight: 1
        $x_1_10 = "%ACCHECK%" wide //weight: 1
        $x_1_11 = "ServerX" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Shark_F_2147606493_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Shark.F"
        threat_id = "2147606493"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Shark"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 00 65 00 78 00 65 00 [0-16] 7c 00 7c 00 7c 00 [0-16] 74 00 65 00 6d 00 70 00 [0-24] 2e 00 65 00 78 00 65 00 [0-16] 70 00 34 00 35 00 35 00 77 00 30 00 72 00 64 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

