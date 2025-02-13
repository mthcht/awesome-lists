rule Backdoor_Win32_Folpsy_A_2147582008_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Folpsy.A!dll"
        threat_id = "2147582008"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Folpsy"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Logged On At %d/%d/%d %d:%d:%d" ascii //weight: 1
        $x_1_2 = "%101u  <DIR>" ascii //weight: 1
        $x_1_3 = "Fail To Recieve()" ascii //weight: 1
        $x_1_4 = "-->Delete A" ascii //weight: 1
        $x_1_5 = "Clean %s Event" ascii //weight: 1
        $x_1_6 = "32First() Fail:Error %d" ascii //weight: 1
        $x_1_7 = "Drive %s (FOLPPY)" ascii //weight: 1
        $x_1_8 = "(Unknow)" ascii //weight: 1
        $x_1_9 = "Uptime: %-.2d Days" ascii //weight: 1
        $x_1_10 = "Plz input password:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (8 of ($x*))
}

