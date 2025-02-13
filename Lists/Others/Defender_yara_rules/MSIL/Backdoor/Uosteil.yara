rule Backdoor_MSIL_Uosteil_A_2147709917_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Uosteil.A"
        threat_id = "2147709917"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Uosteil"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "keyloggeractive" ascii //weight: 1
        $x_1_2 = "Persistence" ascii //weight: 1
        $x_1_3 = "stealfirefox" ascii //weight: 1
        $x_1_4 = "downloadandexecute" ascii //weight: 1
        $x_1_5 = {4d 65 6c 74 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Backdoor_MSIL_Uosteil_A_2147709917_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Uosteil.A"
        threat_id = "2147709917"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Uosteil"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "/entry/ffinput.php" wide //weight: 1
        $x_1_2 = "entry/keyinput.php" wide //weight: 1
        $x_1_3 = {63 00 6c 00 65 00 61 00 6e 00 73 00 65 00 ?? ?? 75 00 70 00 64 00 61 00 74 00 65 00}  //weight: 1, accuracy: Low
        $x_1_4 = {6b 00 65 00 79 00 6c 00 6f 00 67 00 67 00 65 00 72 00 ?? ?? 6d 00 69 00 6e 00 65 00}  //weight: 1, accuracy: Low
        $x_1_5 = {63 00 6c 00 69 00 70 00 62 00 6f 00 61 00 72 00 64 00 ?? ?? 75 00 64 00 70 00 ?? ?? 73 00 79 00 6e 00}  //weight: 1, accuracy: Low
        $x_1_6 = "\\crhost.exe" wide //weight: 1
        $x_1_7 = "/C choice /C Y /N /D Y /T 3 & Del \"" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

