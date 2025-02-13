rule Ransom_Win64_Knight_ZA_2147853198_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Knight.ZA!MTB"
        threat_id = "2147853198"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Knight"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 63 c8 ff c3 48 b8 [0-10] 48 f7 e1 48 c1 ea ?? 48 6b c2 ?? 48 2b c8 0f be 44 0c ?? 66 41 89 06 4d 8d 76 ?? 3b 9c 24 ?? ?? ?? ?? 72}  //weight: 1, accuracy: Low
        $x_1_2 = {42 8a 4c 04 ?? 41 8d 40 ?? 41 30 09 45 33 c0 49 ff c1 83 f8 ?? 44 0f 45 c0 49 83 ea ?? 75}  //weight: 1, accuracy: Low
        $x_1_3 = {47 00 45 00 c7 ?? ?? 54 00 00 00 ff}  //weight: 1, accuracy: Low
        $x_1_4 = {73 00 3a 00 [0-10] 2f 00 2f 00 e8 ?? ?? 00 00 81 3b 68 74 74 70}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Knight_ZA_2147853198_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Knight.ZA!MTB"
        threat_id = "2147853198"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Knight"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Your data is stolen and encrypted" ascii //weight: 1
        $x_1_2 = "\"note_file_name\": \"README_" ascii //weight: 1
        $x_1_3 = "http://ransom" ascii //weight: 1
        $x_1_4 = "cmd.exe /c vssadmin.exe Delete" ascii //weight: 1
        $x_1_5 = "\"kill_services\": [\"" ascii //weight: 1
        $x_1_6 = "\"white_files\": [\"NTUSER.DAT\"" ascii //weight: 1
        $x_1_7 = "Only process smb hosts inside defined host. -host" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Knight_ZB_2147904413_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Knight.ZB!MTB"
        threat_id = "2147904413"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Knight"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Inf-Inf-key.bat.cmd.com.exe.ico" ascii //weight: 1
        $x_1_2 = "at +0330+0430+0530+0545+0630+0845+1030+1245+1345-0930-pass.jpge" ascii //weight: 1
        $x_1_3 = "-local.local.onion/Quiet" ascii //weight: 1
        $x_1_4 = "Value>%s.lock" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Knight_ZC_2147905422_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Knight.ZC!MTB"
        threat_id = "2147905422"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Knight"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "+Inf-Inf.bat.cmd.com.exe.png" ascii //weight: 1
        $x_1_2 = "local.onion/quiet" ascii //weight: 1
        $x_1_3 = "\"kill_services\\\"\"; SetWallpaper" ascii //weight: 1
        $x_1_4 = "\"net_spread\\\"\"; SelfDelete" ascii //weight: 1
        $x_1_5 = "avx512chan<-domainenableexec" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

