rule Ransom_Win32_Akira_A_2147847316_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Akira.A!ibt"
        threat_id = "2147847316"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Akira"
        severity = "Critical"
        info = "ibt: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "the internal infrastructure of your company is fully or partially dead, all your backups" ascii //weight: 10
        $x_1_2 = "-----BEGIN PUBLIC KEY-----" ascii //weight: 1
        $x_1_3 = "Keep in mind that the faster you will get in touch, the less damage we cause." ascii //weight: 1
        $x_1_4 = "powershell.exe -Command \"Get-WmiObject Win32_Shadowcopy | Remove-WmiObject\"" ascii //weight: 1
        $x_1_5 = "D:\\vcprojects\\akira\\asio" ascii //weight: 1
        $x_1_6 = {68 74 74 70 73 3a 2f 2f 61 6b 69 72 61 6c ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? [0-21] 2e 6f 6e 69 6f 6e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Akira_B_2147907860_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Akira.B!ibt"
        threat_id = "2147907860"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Akira"
        severity = "Critical"
        info = "ibt: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "akira_readme.txt" ascii //weight: 4
        $x_1_2 = {2e 00 73 00 71 00 6c 00 69 00 74 00 65 00 33 00 00 00 00 00 00 00 00 00 2e 00 73 00 71 00 6c 00 69 00 74 00 65 00 00 00 2e 00 73 00 71 00 6c 00 00 00 00 00 00 00 00 00 2e 00 73 00 70 00 71 00 00 00 00 00 00 00 00 00 2e 00 74 00 6d 00 64 00 00 00 00 00 00 00 00 00 2e 00 74 00 65 00 6d 00 78}  //weight: 1, accuracy: High
        $x_1_3 = {61 00 63 00 63 00 64 00 63 00 00 00 00 00 2e 00 61 00 63 00 63 00 64 00 62 00 00 00 00 00 2e 00 34 00 64 00 6c 00 00 00 00 00 00 00 00 00 2e 00 34 00 64 00 64 00 00 00 00 00 00 00 00 00 2e 00 61 00 63 00 63 00 66 00 74 00 00 00 00 00 2e 00 61 00 63 00 63 00 64 00 74}  //weight: 1, accuracy: High
        $x_1_4 = {2e 00 64 00 62 00 63 00 00 00 00 00 00 00 00 00 2e 00 64 00 62 00 33 00 00 00 00 00 00 00 00 00 2e 00 64 00 62 00 2d 00 77 00 61 00 6c 00 00 00 2e 00 64 00 62 00 2d 00 73 00 68 00 6d 00 00 00 2e 00 64 00 62 00 76 00 00 00 00 00 00 00 00 00 2e 00 64 00 62 00 74 00 00 00 00 00 00 00 00 00 2e 00 64 00 62 00 73 00 00 00 00 00 00 00 00 00 2e 00 64 00 62 00 66}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

