rule Ransom_Win64_Nova_MA_2147850246_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Nova.MA!MTB"
        threat_id = "2147850246"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Nova"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".README.txt" ascii //weight: 1
        $x_1_2 = "Your unique network Id: " ascii //weight: 1
        $x_1_3 = "Your computers and servers are encrypted, backups are deleted" ascii //weight: 1
        $x_1_4 = "We use strong encryption algorithms, so you cannot decrypt your data" ascii //weight: 1
        $x_1_5 = "we care about nothing but your money" ascii //weight: 1
        $x_1_6 = "Do not rename encrypted files" ascii //weight: 1
        $x_1_7 = "://t.me/NovaGroup2023" ascii //weight: 1
        $x_1_8 = "email at novagroup@onionmail" ascii //weight: 1
        $x_1_9 = "ransomware is a part of the world of cyber security" ascii //weight: 1
        $x_1_10 = "you got hacked" ascii //weight: 1
        $x_1_11 = "The virus has the ability to self-destruct" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Nova_GTV_2147960923_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Nova.GTV!MTB"
        threat_id = "2147960923"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Nova"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "README-NOVA.me" ascii //weight: 1
        $x_1_2 = "you under controll by Nova ransomware" ascii //weight: 1
        $x_1_3 = "nova_encryptor.pdb" ascii //weight: 1
        $x_1_4 = "do not touch the files becouse we can't decrypt it if you touch it" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Nova_DA_2147970501_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Nova.DA!MTB"
        threat_id = "2147970501"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Nova"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "README-NOVA.me" ascii //weight: 1
        $x_1_2 = ".praktiknv" ascii //weight: 1
        $x_1_3 = "http://nova" ascii //weight: 1
        $x_1_4 = "do not touch the files" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Nova_A_2147971729_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Nova.A"
        threat_id = "2147971729"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Nova"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[SHADOW] Deleting all volume shadow copies..." ascii //weight: 1
        $x_1_2 = "[EVENT LOGS] Deleting Windows event logs..." ascii //weight: 1
        $x_1_3 = "[EDR KILL] Attempting to kill EDR/AV processes..." ascii //weight: 1
        $x_1_4 = "[DELETE] Preserving key.txt for decryption reference" ascii //weight: 1
        $x_1_5 = "Failed to create worker copy" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

