rule Backdoor_Win32_Mailtrol_A_2147772378_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Mailtrol.A"
        threat_id = "2147772378"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Mailtrol"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "github.com/ThomsonReutersEikon/go-ntlm" ascii //weight: 1
        $x_1_2 = "github.com/staaldraad/go-ntlm" ascii //weight: 1
        $x_1_3 = "github.com/urfave/cli" ascii //weight: 1
        $x_1_4 = "sensepost/ruler/" ascii //weight: 1
        $x_1_5 = "C:\\Windows\\System32\\calc.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

