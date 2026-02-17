rule Ransom_Win64_FileCrypter_MA_2147764529_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/FileCrypter.MA!MTB"
        threat_id = "2147764529"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "FileCrypter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Go build ID:" ascii //weight: 1
        $x_1_2 = "as  at  fp= is  lr: of  on  pc= sp: sp=%x" ascii //weight: 1
        $x_1_3 = "Inf.bat.cmd.com.css.exe.gif.htm.jpg.mjs.pdf.png.svg.xml" ascii //weight: 1
        $x_1_4 = "main.ransomNote" ascii //weight: 1
        $x_1_5 = ".encrypted" ascii //weight: 1
        $x_1_6 = "unreachableuserenv.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_FileCrypter_NC_2147925077_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/FileCrypter.NC!MTB"
        threat_id = "2147925077"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "FileCrypter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Once the money have been recieved, your files will be automatically decrypted" ascii //weight: 2
        $x_2_2 = "YOUR SYSTEM IS COMPROMISED! READ THIS MESSAGE CAREFULLY!" ascii //weight: 2
        $x_1_3 = "and all your system has been hijacked. Meaning we have access to ALL YOUR FILES" ascii //weight: 1
        $x_1_4 = "All your files have been encrypted," ascii //weight: 1
        $x_1_5 = "for anyone to download. This includes your personal data, passwords, and more" ascii //weight: 1
        $x_1_6 = "YOU ARE RESPONSIBLE FOR PAYING THE MONEY, IF YOU MESS IT UP IT IS YOUR FAULT" ascii //weight: 1
        $x_1_7 = "all your files will be public on the internet" ascii //weight: 1
        $x_1_8 = "Set-MpPreference -DisableRealtimeMonitoring $true" ascii //weight: 1
        $x_1_9 = "Set-MpPreference -DisableCloudProtection $true" ascii //weight: 1
        $x_1_10 = "ransomware" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_FileCrypter_GHM_2147963158_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/FileCrypter.GHM!MTB"
        threat_id = "2147963158"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "FileCrypter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "api.valentinesforever.thm" ascii //weight: 1
        $x_1_2 = "1L0v3Y0uF0r3v3r4ndEv3r2024xoxo" ascii //weight: 1
        $x_1_3 = "Your data has been exfiltrated" ascii //weight: 1
        $x_1_4 = "YOUR FILES HAVE BEEN ENCRYPTED" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

