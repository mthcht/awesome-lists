rule Trojan_MSIL_Filecoder_AGC_2147783706_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Filecoder.AGC!MTB"
        threat_id = "2147783706"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "eiklot@hi2.in" ascii //weight: 1
        $x_1_2 = "How_Recover_Files.txt" ascii //weight: 1
        $x_1_3 = "JesusCrypt" ascii //weight: 1
        $x_1_4 = "EncryptFile" ascii //weight: 1
        $x_1_5 = "SendServerInfo@hitler.rocks" ascii //weight: 1
        $x_1_6 = "mail.cock.li" ascii //weight: 1
        $x_1_7 = "Jesus_Ransom" ascii //weight: 1
        $x_1_8 = "All Your Files Encrypted By Jesus Ransomware" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Filecoder_AJM_2147787829_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Filecoder.AJM!MTB"
        threat_id = "2147787829"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".[xmrlocker]" wide //weight: 1
        $x_1_2 = "readme(howtodecrypt).txt" wide //weight: 1
        $x_1_3 = "All your files are encrypted by lockxmr@daum.net" wide //weight: 1
        $x_1_4 = "lockxmr@airmail.cc" wide //weight: 1
        $x_1_5 = "vssadmin.exe" wide //weight: 1
        $x_1_6 = "Alphaleonis.Win32.Network" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Filecoder_PI_2147788490_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Filecoder.PI!MTB"
        threat_id = "2147788490"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Kraken" ascii //weight: 1
        $x_1_2 = "extension_bypass" ascii //weight: 1
        $x_1_3 = "2kHjgBUx6QQSkwRnLs5c/AdbjroDU4j5AanCabrpjBLnKCWGKwmlWQZR" ascii //weight: 1
        $x_1_4 = "GRSYnKNx1qRCoiCPQqL6MjUHEEOXkMOWITh/CacwQDMEEn2SlxDDisLvybdjw9y1Q==" ascii //weight: 1
        $x_1_5 = "target_extensions" ascii //weight: 1
        $x_1_6 = "accdb" ascii //weight: 1
        $x_1_7 = "backup" ascii //weight: 1
        $x_1_8 = "bank" ascii //weight: 1
        $x_1_9 = "blend" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Filecoder_AQS_2147832523_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Filecoder.AQS!MTB"
        threat_id = "2147832523"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 0c 07 08 16 08 8e 69 6f ?? ?? ?? 0a 0d 03 09 28}  //weight: 2, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
        $x_1_3 = "NominatusCrypt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Filecoder_PSKU_2147845493_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Filecoder.PSKU!MTB"
        threat_id = "2147845493"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {72 65 00 00 70 28 1d 00 00 06 0b 28 ?? ?? ?? 0a 07 6f ?? ?? ?? 0a 72 a5 00 00 70 7e ?? ?? ?? 0a 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 0c de 0d}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Filecoder_PSOW_2147847861_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Filecoder.PSOW!MTB"
        threat_id = "2147847861"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 72 53 34 00 70 28 ?? ?? ?? 0a 26 72 71 34 00 70 72 87 34 00 70 28 ?? ?? ?? 0a 26 72 91 34 00 70 72 87 34 00 70 28 ?? ?? ?? 0a 26 72 ab 34 00 70 72 bf 34 00 70 28 ?? ?? ?? 0a 26 72 cb 34 00 70 72 db 34 00 70}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Filecoder_PSSE_2147850765_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Filecoder.PSSE!MTB"
        threat_id = "2147850765"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {26 07 06 6f 30 00 00 0a 16 73 2c 00 00 0a 0c 00 04 18 73 29 00 00 0a 0d 00 20 00 00 10 00 8d 2a 00 00 01 13 04 2b 0e}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Filecoder_PSVP_2147888534_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Filecoder.PSVP!MTB"
        threat_id = "2147888534"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {06 06 6f 25 00 00 0a 06 6f ?? 00 00 0a 6f ?? 00 00 0a 0b 28 ?? 00 00 0a 7e 03 00 00 04 28 ?? 00 00 0a 07}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Filecoder_PTBG_2147895561_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Filecoder.PTBG!MTB"
        threat_id = "2147895561"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6f 20 00 00 0a 13 0b 11 08 08 16 08 8e 69 6f 21 00 00 0a 11 08 6f 22 00 00 0a 09 11 0b 28 ?? 00 00 2b 28 ?? 00 00 2b 0d 09 11 07}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Filecoder_AWA_2147923697_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Filecoder.AWA!MTB"
        threat_id = "2147923697"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "VoidCrypt encrypted all of your files." ascii //weight: 2
        $x_2_2 = "There is no way to recover any files." ascii //weight: 2
        $x_2_3 = "Each file has been encrypted using RSA." ascii //weight: 2
        $x_2_4 = "There is nothing left on your system except the OS." ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Filecoder_ASA_2147924725_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Filecoder.ASA!MTB"
        threat_id = "2147924725"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "DELETE THE BACKUP CATALOG" wide //weight: 2
        $x_2_2 = "DELETE SHADOW COPIES" wide //weight: 2
        $x_2_3 = "ECNRYPT NETWORK FOLDERS" wide //weight: 2
        $x_2_4 = "DISABLE RECOVERY MODE" wide //weight: 2
        $x_2_5 = "REMOVE BACKUP FILES" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Filecoder_WA_2147927335_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Filecoder.WA!MTB"
        threat_id = "2147927335"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "trinexis.com/passwords/" wide //weight: 3
        $x_3_2 = "z oktay@oktay.com mail adresiyle ileti" wide //weight: 3
        $x_2_3 = "ifrelendi ve README.txt dosyas" wide //weight: 2
        $x_2_4 = "GetDirectories" ascii //weight: 2
        $x_2_5 = "$05a622d6-6546-4925-9648-106ea5403a90" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Filecoder_WI_2147929450_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Filecoder.WI!MTB"
        threat_id = "2147929450"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "!00_UNLIZARD_INSTRUCTIONS.txt" wide //weight: 2
        $x_2_2 = "PAY {0} to {1}" wide //weight: 2
        $x_2_3 = "to receive your key and decryptor to get back your data!" wide //weight: 2
        $x_2_4 = "$b366f8f1-c284-4474-93f7-f91ead735f68" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Filecoder_SWA_2147940146_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Filecoder.SWA!MTB"
        threat_id = "2147940146"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {06 16 07 8e 69 6f ?? 00 00 0a 13 04 08 09 07 11 04 93 9d 09 17 58 0d 09 1f 1b 32 e4}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Filecoder_MBZ_2147942167_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Filecoder.MBZ!MTB"
        threat_id = "2147942167"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0b 02 06 07 28 ?? 00 00 06 0c 03 08 28 ?? 00 00 0a 00 03 03 72 ff 00 00 70}  //weight: 2, accuracy: Low
        $x_1_2 = "64b54f4acb8d" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Filecoder_EBIO_2147946272_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Filecoder.EBIO!MTB"
        threat_id = "2147946272"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {5f 0b 03 1b 5a 03 1d 63 5f 03 1f 0c 63 60 1f 7f 5f 0c 03 1f 2a 03 1f 0a 63 5f 5a 03 1e 63 61 1f 3f 5f 0d}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

