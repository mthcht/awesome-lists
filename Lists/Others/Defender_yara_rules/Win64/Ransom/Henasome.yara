rule Ransom_Win64_Henasome_P_2147753158_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Henasome.P!MTB"
        threat_id = "2147753158"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Henasome"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "All your files have been encrypted with a random key and no decryption tool can save them" ascii //weight: 1
        $x_1_2 = "iaminfected.sac@elude.i" ascii //weight: 1
        $x_1_3 = "We are not scammers, your files will be unlocked if you pay" ascii //weight: 1
        $x_1_4 = "If you would like to regain access to your files, please make a $100 donation to Silicon Venom" ascii //weight: 1
        $x_1_5 = "vssadmin.exe Delete Shadows /All /Quiet" ascii //weight: 1
        $x_1_6 = ":\\ProgramData\\cmdkey.bat" ascii //weight: 1
        $x_1_7 = ":\\Windows\\System32\\cmdkey.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Ransom_Win64_Henasome_MA_2147832359_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Henasome.MA!MTB"
        threat_id = "2147832359"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Henasome"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {c1 e3 08 31 d8 0f b6 5c 35 ?? c1 e3 ?? 31 d8 33 84 8d ?? ?? ?? ?? 89 47 ?? 33 47 ?? 89 47 ?? 33 47 ?? 89 47 ?? 33 47 ?? 89 47 ?? 83 c1 ?? 48 8d 7f ?? 83 f9 ?? 7c}  //weight: 5, accuracy: Low
        $x_1_2 = ".royal" wide //weight: 1
        $x_1_3 = "delete shadows /all /quiet" ascii //weight: 1
        $x_1_4 = "SUATAUAVAWH" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Henasome_AA_2147954062_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Henasome.AA!MTB"
        threat_id = "2147954062"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Henasome"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "files in the specified directory have been encrypted" ascii //weight: 1
        $x_1_2 = "Starting local encryption" ascii //weight: 1
        $x_1_3 = "delete shadow copies" ascii //weight: 1
        $x_1_4 = "README.TXT" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

