rule Ransom_Win64_Clop_F_2147844011_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Clop.F"
        threat_id = "2147844011"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Clop"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "temp.ocx" wide //weight: 1
        $x_1_2 = "ENDOEFEND123" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Clop_SM_2147847140_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Clop.SM!dha"
        threat_id = "2147847140"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Clop"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%s\\A_TEXT_READ_ME_A.TXT" wide //weight: 1
        $x_1_2 = "%s runrun" wide //weight: 1
        $x_1_3 = ".CL_0_P" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Clop_SA_2147849470_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Clop.SA!MTB"
        threat_id = "2147849470"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Clop"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 04 24 ff c0 25 ?? ?? ?? ?? 88 04 24 0f b6 04 24 48 8b 4c 24 ?? 0f b6 04 01 0f b6 4c 24 ?? 03 c1 25 ?? ?? ?? ?? 88 44 24}  //weight: 1, accuracy: Low
        $x_1_2 = {41 0f b6 14 10 03 ca 81 e1 ?? ?? ?? ?? 48 63 c9 48 8b 54 24 ?? 0f b6 0c 0a 48 ?? ?? ?? ?? 0f b6 04 02 33 c1 8b 4c 24 ?? 48 ?? ?? ?? ?? 88 04 0a e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Clop_J_2147906483_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Clop.J"
        threat_id = "2147906483"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Clop"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2a 00 2e 00 2a 00 00 00 25 00 73 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 4f 00 75 00 74 00 6c 00 6f 00 6f 00 6b 00}  //weight: 1, accuracy: High
        $x_1_2 = {25 00 73 00 5c 00 21 00 [0-32] 5f 00 52 00 45 00 41 00 44 00 5f 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Clop_KWAA_2147907932_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Clop.KWAA!MTB"
        threat_id = "2147907932"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Clop"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%s\\Microsoft\\Outlook" wide //weight: 1
        $x_1_2 = "%s\\Microsoft\\Word" wide //weight: 1
        $x_1_3 = "%s\\Microsoft\\Office" wide //weight: 1
        $x_1_4 = "OVERFILEEND" wide //weight: 1
        $x_1_5 = "%s\\AAA_READ_AAA.TXT" wide //weight: 1
        $x_1_6 = ".C_-_L_-_0_-_P" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Clop_A_2147919384_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Clop.A"
        threat_id = "2147919384"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Clop"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "net stop mozyprobackup /y" ascii //weight: 1
        $x_1_2 = "net stop EraserSvc11710 /y" ascii //weight: 1
        $x_1_3 = "net stop SstpSvc /y" ascii //weight: 1
        $x_1_4 = "net stop MSSQLSERVER /y" ascii //weight: 1
        $x_1_5 = "net stop SQLWriter /y" ascii //weight: 1
        $x_1_6 = "too many files open in system" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Clop_AMCV_2147928846_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Clop.AMCV!MTB"
        threat_id = "2147928846"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Clop"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {48 8b c2 83 e0 7f 0f b6 0c 38 0f b6 44 14 ?? 32 c8 88 4c 14 ?? 48 ff c2 48 83 fa}  //weight: 5, accuracy: Low
        $x_5_2 = "vssadmin Delete Shadows /all /quiet" ascii //weight: 5
        $x_4_3 = "cmd.exe /c timeout 7 & del \"%s\"" ascii //weight: 4
        $x_2_4 = "Ignoring file with blocklisted extension" ascii //weight: 2
        $x_2_5 = "Ignoring blocklisted directory" ascii //weight: 2
        $x_1_6 = "net stop \"SQLsafe Filter Service\" /y" ascii //weight: 1
        $x_1_7 = "net stop ReportServer /y" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

