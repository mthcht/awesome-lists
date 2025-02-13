rule Ransom_Win64_BianLian_B_2147829630_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/BianLian.B!MSR"
        threat_id = "2147829630"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "BianLian"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Your network systems were attacked and encrypted" ascii //weight: 1
        $x_1_2 = "Look at this instruction.txt" ascii //weight: 1
        $x_1_3 = "bianlian" ascii //weight: 1
        $x_1_4 = "text=  zombie" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_BianLian_PA_2147830712_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/BianLian.PA!MTB"
        threat_id = "2147830712"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "BianLian"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6d 61 69 6e 2e 65 6e 63 72 79 70 74 00}  //weight: 1, accuracy: High
        $x_1_2 = "Go build ID:" ascii //weight: 1
        $x_1_3 = "crypto/cipher.xorBytesSSE2" ascii //weight: 1
        $x_1_4 = "Look at this instruction.txt" ascii //weight: 1
        $x_1_5 = "bianlian244140625" ascii //weight: 1
        $x_1_6 = "text=  zombie" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_BianLian_PB_2147837940_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/BianLian.PB!MTB"
        threat_id = "2147837940"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "BianLian"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f1 d5 00 fa 4c 62 cc f4 0f 0b}  //weight: 1, accuracy: High
        $x_10_2 = "Go build ID:" ascii //weight: 10
        $x_10_3 = {48 8b 54 24 ?? 48 8d 4a ?? 48 8b 84 24 [0-4] 48 8b 54 24 ?? 48 39 ca 0f 8e [0-4] 48 89 4c 24 ?? 48 8b b4 24 [0-4] 48 89 f7 48 0f af f1 48 03 35 ?? ?? ?? ?? 48 89 b4 24 [0-4] 48 89 c3 48 8b 84 24 [0-4] 48 89 f9 e8 [0-4] 48 8b b4 24 [0-4] 48 39 f0 75}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_BianLian_PC_2147838463_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/BianLian.PC!MTB"
        threat_id = "2147838463"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "BianLian"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f1 d5 00 fa 4c 62 cc f4 0f 0b}  //weight: 1, accuracy: High
        $x_2_2 = {69 74 27 73 20 63 6f 6d 70 6c 65 74 65 20 6c 6f 73 73 2e 0d 0a ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 49 6e 20 31 30 20 64 61 79 73 20 2d 20}  //weight: 2, accuracy: Low
        $x_2_3 = {6d 61 69 6e 2e 53 63 61 6e 46 6f 72 46 69 6c 65 73 2e 66 75 6e 63 31 ?? 6d 61 69 6e 2e 6d 61 69 6e}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win64_BianLian_OBS_2147917696_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/BianLian.OBS!MTB"
        threat_id = "2147917696"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "BianLian"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Starting BianLian emulation" ascii //weight: 1
        $x_2_2 = "rundll32.exe runcalc.dll,emptyzip" ascii //weight: 2
        $x_2_3 = "trellix.digital" ascii //weight: 2
        $x_1_4 = "All your files have been encrypted. Pay the ransom to get them back" ascii //weight: 1
        $x_1_5 = "Look at this instruction.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_BianLian_FEM_2147920134_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/BianLian.FEM!MTB"
        threat_id = "2147920134"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "BianLian"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {50 58 89 84 24 88 00 00 00 48 8b ac 24 a0 00 00 00 4c 0f be 7d 00 48 63 84 24 88 00 00 00 49 31 c7 4c 89 f8 50 48 8b ac 24 a8 00 00 00 58 88 45 00 4c 8b bc 24 a0 00 00 00 49 ff c7 4c 89 bc 24 a0 00 00 00 ff 44 24 78}  //weight: 5, accuracy: High
        $x_1_2 = "bcdedit.exe /set loadoptions DDISABLE_INTEGRITY_CHECKS" ascii //weight: 1
        $x_1_3 = "sc create winppx binPath" ascii //weight: 1
        $x_1_4 = "revsoks.bat" ascii //weight: 1
        $x_1_5 = "Zz158df@jniow45h@" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

