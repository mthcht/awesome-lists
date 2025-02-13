rule Ransom_Win32_BankiaCry_AJY_2147772931_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/BankiaCry.AJY!MSR"
        threat_id = "2147772931"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "BankiaCry"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "BankiaCry.exe" ascii //weight: 1
        $x_1_2 = "C:\\Users\\chacel\\source\\repos\\ransom\\ransom\\BankiaCry\\obj\\x64\\Debug\\BankiaCry.pdb" ascii //weight: 1
        $x_1_3 = "Your computer is encrypted!! All your data belongs to us!" ascii //weight: 1
        $x_1_4 = "bankia-server.com" ascii //weight: 1
        $x_1_5 = "\\README!!!!.TXT" ascii //weight: 1
        $x_1_6 = "SELECT SystemSKUNumber from Win32_ComputerSystem" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

