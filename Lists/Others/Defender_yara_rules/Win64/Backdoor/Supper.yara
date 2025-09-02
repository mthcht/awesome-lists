rule Backdoor_Win64_Supper_A_2147917250_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/Supper.A!ldr"
        threat_id = "2147917250"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "Supper"
        severity = "Critical"
        info = "ldr: loader component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b 04 1f 48 33 45 f0 48 89 04 1e e8 ?? ?? ?? ?? 48 3b 45 e0 0f 83 ?? ?? ?? ?? 48 31 c9 51 48 8d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win64_Supper_B_2147920400_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/Supper.B"
        threat_id = "2147920400"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "Supper"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 81 7d 10 ff 3f 0f ?? ?? ?? ?? ?? 0f b7 45 10 48 98 48 8d 14 c5 00 00 00 00 48 8d}  //weight: 1, accuracy: Low
        $x_1_2 = {81 7d fc ff 3f 00 00 0f ?? ?? ?? ?? ?? 48 8b 05 5e 3e 02 00 48 85 c0 74 ?? 48 8b 05 52 3e 02 00 48 89 c1 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Backdoor_Win64_Supper_D_2147927457_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/Supper.D"
        threat_id = "2147927457"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "Supper"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "schtasks.exe /Create /SC MINUTE /TN GoogleUpdateTask /TR \"cmd.exe /C del \\\"%s\\\" && schtasks.exe /Delete /TN GoogleUpdateTask /F\" /F" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

