rule Ransom_Win32_Pryncimoklyn_A_2147721271_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Pryncimoklyn.A"
        threat_id = "2147721271"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Pryncimoklyn"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {36 36 85 c9 74 ?? c1 c0 07 0f b7 c9 8d 52 02 33 c1 0f b7 0a 66 85 c9 75}  //weight: 1, accuracy: Low
        $x_1_2 = "00AE%08X" wide //weight: 1
        $x_1_3 = "/scripts/superfish/js/supersubs.php" ascii //weight: 1
        $x_1_4 = "212.47.254.187" ascii //weight: 1
        $x_1_5 = "%s\\INSTRUCTION_FOR_HELPING_FILE_RECOVERY.TXT" ascii //weight: 1
        $x_1_6 = "%s%08X%08X%08X%08X." wide //weight: 1
        $x_1_7 = "bcdedit /set {default} recoveryenabled No" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Ransom_Win32_Pryncimoklyn_A_2147721272_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Pryncimoklyn.A!!Pryncimoklyn.gen!A"
        threat_id = "2147721272"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Pryncimoklyn"
        severity = "Critical"
        info = "Pryncimoklyn: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {36 36 85 c9 74 ?? c1 c0 07 0f b7 c9 8d 52 02 33 c1 0f b7 0a 66 85 c9 75}  //weight: 1, accuracy: Low
        $x_1_2 = "00AE%08X" ascii //weight: 1
        $x_1_3 = "/scripts/superfish/js/supersubs.php" ascii //weight: 1
        $x_1_4 = "212.47.254.187" ascii //weight: 1
        $x_1_5 = "%s\\INSTRUCTION_FOR_HELPING_FILE_RECOVERY.TXT" ascii //weight: 1
        $x_1_6 = "%s%08X%08X%08X%08X." ascii //weight: 1
        $x_1_7 = "bcdedit /set {default} recoveryenabled No" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Ransom_Win32_Pryncimoklyn_A_2147722008_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Pryncimoklyn.A!!Pryncimoklyn.A!rsm"
        threat_id = "2147722008"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Pryncimoklyn"
        severity = "Critical"
        info = "Pryncimoklyn: an internal category used to refer to some threats"
        info = "A: an internal category used to refer to some threats"
        info = "rsm: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "400"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "_HELP_INSTRUCTION.TXT" wide //weight: 100
        $x_100_2 = "%s%08X%08X%08X%08X.MOLE02" wide //weight: 100
        $x_100_3 = "vssadmin.exe Delete Shadows /All /Quiet" ascii //weight: 100
        $x_100_4 = "!!! Your DECRYPT-ID: %s !!!" wide //weight: 100
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

