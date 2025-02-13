rule Ransom_Win32_Robbinhood_B_2147759247_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Robbinhood.B!dha"
        threat_id = "2147759247"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Robbinhood"
        severity = "Mid"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "RBNLDrv" ascii //weight: 1
        $x_1_2 = {70 4c 69 73 74 2e 74 78 74 [0-8] 72 6f 62 6e 72 2e 73 79 73}  //weight: 1, accuracy: Low
        $x_1_3 = {8a 0c 37 80 e9 ?? 88 0c 30 46 3b f5 7c ba}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Ransom_Win32_Robbinhood_B_2147759247_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Robbinhood.B!dha"
        threat_id = "2147759247"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Robbinhood"
        severity = "Mid"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "50"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "at  fp= is  lr: of  on  pc= sp: sp=" ascii //weight: 10
        $x_10_2 = "JFJlY3ljbGUuQmluJFdJTkRPV1MufkJU" ascii //weight: 10
        $x_10_3 = "m=+Inf, n -Inf.bat.cmd.com.exe" ascii //weight: 10
        $x_10_4 = "Go build ID:" ascii //weight: 10
        $x_10_5 = "U09QSE9TTVNTUUwkUFJPRA" ascii //weight: 10
        $x_10_6 = "function.enc_robbin_hood" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Ransom_Win32_Robbinhood_B_2147759247_2
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Robbinhood.B!dha"
        threat_id = "2147759247"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Robbinhood"
        severity = "Mid"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "at  fp= is  lr: of  on  pc= sp: sp=" ascii //weight: 10
        $x_10_2 = "(nil)+0330+0430+0530+0545+0630+0845+1030+1245+1345, ..., fp:-0930." ascii //weight: 10
        $x_10_3 = ".rbhd" ascii //weight: 10
        $x_10_4 = "Go build ID: \"te2kDHCtcNEzM793uSK-/qcX4_9l5TMx0upjvHY1c/6wAv8MU9rb9S69d0iU8U/aFx7UDqYGYkpNLCqBo1P\"" ascii //weight: 10
        $x_10_5 = "Go build ID: \"qp9Xe0v8Zzt9IwBj9_Wt/tilZJP1eGWylLw-kTJuw/Bqr7IIku6bame9non3UZ/fLk4axx9eYm_wDu6J7Xk\"" ascii //weight: 10
        $x_10_6 = "Go build ID: \"GbDR9syJNsY0KEkc2yeo/WxCLZBUe_KSPefUo9FaI/iK00GaI0oV_ZuXJMjnzq/gfJBwJ_2fRFj5LH7GU_Q\"" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Ransom_Win32_Robbinhood_C_2147759248_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Robbinhood.C!dha"
        threat_id = "2147759248"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Robbinhood"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {67 6f 2f 73 72 63 2f 4e 65 77 42 6f 73 73 01 00 2f 6d 61 69 6e 2e 67 6f}  //weight: 1, accuracy: Low
        $x_10_2 = "go/src/NewBoss2/main.go" ascii //weight: 10
        $x_5_3 = "_Square\\up\\winlogon.exe" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Robbinhood_A_2147759249_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Robbinhood.A"
        threat_id = "2147759249"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Robbinhood"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd.exe /c sc.exe stop BackupExecManagementService" ascii //weight: 1
        $x_1_2 = "cmd.exe /c sc.exe stop \"Sophos File Scanner Service\"" ascii //weight: 1
        $x_1_3 = "cmd.exe /c sc.exe stop MSSQLFDLauncher$SBSMONITORING" ascii //weight: 1
        $x_1_4 = "cmd.exe /c sc.exe stop McAfeeFrameworkMcAfeeFrame" ascii //weight: 1
        $x_1_5 = "cmd.exe /c sc.exe stop ReportServer$SYSTEM_BGC" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

