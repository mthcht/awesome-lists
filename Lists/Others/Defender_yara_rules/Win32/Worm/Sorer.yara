rule Worm_Win32_Sorer_A_2147603504_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Sorer.A"
        threat_id = "2147603504"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Sorer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {49 66 57 69 6e 45 78 69 73 74 2c 20 57 69 6e 61 6d 70 0d 0a 7b 0d 0a 0d 0a 43 6f 6e 74 72 6f 6c 46 6f 63 75 73 2c 20 2c 20 57 69 6e 61 6d 70 0d 0a 53 65 6e 64 20 21 7b 46 34 7d 0d 0a 4d 73 67 42 6f 78 20 34 31 31 32 2c 4d 69 63 72 6f 73 6f 66 74 20 57 69 6e 64 6f 77 73 20 57 61 72 6e 69 6e 67 2c 22 57 65 20 61 72 65 20 73 6f 72 72 79}  //weight: 1, accuracy: High
        $x_1_2 = "FileCopy,C:\\WINDOWS\\system\\Autorun.inf,%" ascii //weight: 1
        $x_1_3 = "FileCopy,C:\\WINDOWS\\system\\svc.exe,%" ascii //weight: 1
        $x_1_4 = {49 66 57 69 6e 45 78 69 73 74 2c 20 56 4c 43 0d 0a 7b 0d 0a 77 69 6e 63 6c 6f 73 65}  //weight: 1, accuracy: High
        $x_1_5 = "Microsoft Windows,\"You are using a pirated(illegal) version of Microsoft.`nYou may encounter severe Penalties for this kind of action.`nPlease Register your copy at www.microsoft.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

