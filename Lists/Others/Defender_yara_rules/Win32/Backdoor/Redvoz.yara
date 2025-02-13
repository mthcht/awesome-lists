rule Backdoor_Win32_Redvoz_A_2147598348_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Redvoz.A"
        threat_id = "2147598348"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Redvoz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "service, res=" ascii //weight: 1
        $x_1_2 = "InjectionThread complete" ascii //weight: 1
        $x_1_3 = "<DLL dies> event" ascii //weight: 1
        $x_1_4 = "trying <%s> with <%s>" ascii //weight: 1
        $x_1_5 = "DLL injected!" ascii //weight: 1
        $x_1_6 = "thread complete (%i)." ascii //weight: 1
        $x_1_7 = "thread injected (%i)." ascii //weight: 1
        $x_1_8 = "WriteProcessMemory() ok" ascii //weight: 1
        $x_1_9 = "file <%s>" ascii //weight: 1
        $x_1_10 = "writing to HKLM" ascii //weight: 1
        $x_1_11 = "my port [%i]" ascii //weight: 1
        $x_1_12 = "*update \"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (9 of ($x*))
}

