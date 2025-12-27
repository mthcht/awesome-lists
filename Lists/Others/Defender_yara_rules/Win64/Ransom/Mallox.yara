rule Ransom_Win64_Mallox_CCCM_2147892846_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Mallox.CCCM!MTB"
        threat_id = "2147892846"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Mallox"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HOW TO BACK FILES.txt" wide //weight: 1
        $x_1_2 = "-path" wide //weight: 1
        $x_1_3 = "-queue" wide //weight: 1
        $x_1_4 = "C:\\HOW TO RECOVER !!.TXT" wide //weight: 1
        $x_1_5 = "SeDebugPrivilege" wide //weight: 1
        $x_1_6 = "Do NOT shutdown OR reboot your PC: this might damage your files permanently !" wide //weight: 1
        $x_1_7 = "shutdownwithoutlogon" wide //weight: 1
        $x_1_8 = "delete shadows /all /quiet" wide //weight: 1
        $x_1_9 = "SOFTWARE\\Raccine" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Mallox_AMAA_2147909699_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Mallox.AMAA!MTB"
        threat_id = "2147909699"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Mallox"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Your data has been stolen and encrypted" ascii //weight: 1
        $x_1_2 = "We will delete the stolen data and help with the recovery of encrypted files after payment has been made" ascii //weight: 1
        $x_1_3 = "wtyafjyhwqrgo4a45wdvvwhen3cx4euie73qvlhkhvlrexljoyuklaad.onion" ascii //weight: 1
        $x_1_4 = "HOW TO BACK FILES.txt" ascii //weight: 1
        $x_1_5 = "delete shadows /all /quiet" ascii //weight: 1
        $x_1_6 = "SOFTWARE\\Microsoft\\PolicyManager\\default\\Start\\HideRestart" ascii //weight: 1
        $x_1_7 = ".mallox" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Mallox_MKB_2147909723_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Mallox.MKB!MTB"
        threat_id = "2147909723"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Mallox"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 98 41 8b 4c 83 fc 8b c1 c1 e8 1e 33 c1 69 c0 65 89 07 6c 03 d0 49 63 c0 41 89 14 83}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Mallox_AMA_2147915511_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Mallox.AMA!MTB"
        threat_id = "2147915511"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Mallox"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Your data has been stolen and encrypted" ascii //weight: 1
        $x_1_2 = "We will delete the stolen data and help with the recovery of encrypted files after payment has been made" ascii //weight: 1
        $x_1_3 = "Do not try to change or restore files yourself, this will break them" ascii //weight: 1
        $x_1_4 = "We provide free decryption for any 3 files up to 3MB in size on our website" ascii //weight: 1
        $x_1_5 = "Run TOR browser and open the site: wtyafjyhwqrgo4a45wdvvwhen3cx4euie73qvlhkhvlrexljoyuklaad.onion/mallox/privateSignin" ascii //weight: 1
        $x_1_6 = "targetinfo.txt" wide //weight: 1
        $x_1_7 = "delete shadows /all /quiet" wide //weight: 1
        $x_1_8 = "SOFTWARE\\Raccine" wide //weight: 1
        $x_1_9 = "SYSTEM\\CurrentControlSet\\Services\\EventLog\\Application\\Raccine" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Mallox_C_2147946172_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Mallox.C!MTB"
        threat_id = "2147946172"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Mallox"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "Your files has been encrypted" ascii //weight: 3
        $x_3_2 = "delete shadows /all /quiet" wide //weight: 3
        $x_1_3 = "$windows.~ws" wide //weight: 1
        $x_1_4 = "$windows.~bt" wide //weight: 1
        $x_1_5 = "FILE RECOVERY.txt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

