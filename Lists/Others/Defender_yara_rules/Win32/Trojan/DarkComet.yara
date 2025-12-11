rule Trojan_Win32_DarkComet_RDA_2147837232_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DarkComet.RDA!MTB"
        threat_id = "2147837232"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkComet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "REGWRITE ( \"HKLM\" & $PREF & \"\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\"" ascii //weight: 1
        $x_1_2 = "\"ConsentPromptBehaviorAdmin\" , \"REG_DWORD\" , \"0\"" ascii //weight: 1
        $x_1_3 = "\"EnableLUA\" , \"REG_DWORD\" , \"0\"" ascii //weight: 1
        $x_1_4 = "$FILEOPEND = FILEOPEN ( $FILE , 2 + 8 )" ascii //weight: 1
        $x_1_5 = "$DECRYPT = _BASE64DECODE ( $CODE )" ascii //weight: 1
        $x_1_6 = "$EXE = BINARYTOSTRING ( $DECRYPT )" ascii //weight: 1
        $x_1_7 = "SHELLEXECUTE ( $FILE )" ascii //weight: 1
        $x_1_8 = "DIRREMOVE ( @TEMPDIR & \"\\\" & $FILENME , 1 )" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DarkComet_AME_2147844797_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DarkComet.AME!MTB"
        threat_id = "2147844797"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkComet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 d4 8b 4d e8 2b 48 14 8b 45 d4 8b 40 0c 8b 55 d8 8b 75 e4 2b 72 14 8b 55 d8 8b 52 0c 8a 04 08 32 04 32 8b 4d d4 8b 55 e8 2b 51 14 8b 4d d4 8b 49 0c 88 04 11 8b 45 e4 40 89 45 e4 8b 45 e4 3b 45 e0 7e 04 83 65 e4 00 8b 45 e8 40 89 45 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DarkComet_ADK_2147894002_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DarkComet.ADK!MTB"
        threat_id = "2147894002"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkComet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {32 34 00 01 31 00 00 02 31 36 00 01 32 00 00 01 38 00 00 01 33 00 00 01 34 00 00 03 31 32}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DarkComet_ADK_2147894002_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DarkComet.ADK!MTB"
        threat_id = "2147894002"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkComet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 f2 81 e6 ff 00 00 80 79 ?? 4e 81 ce 00 ff ff ff 46 0f b6 94 b5 fc fb ff ff 8b b5 f4 fb ff ff 30 14 06 40 3b c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DarkComet_ADK_2147894002_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DarkComet.ADK!MTB"
        threat_id = "2147894002"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkComet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {50 6a 00 53 68 4c 28 1c 13 6a 00 6a 00 e8 dd 4f f8 ff db 6d e8 d8 25 24 2b 1c 13 db 7d e8 9b db 6d e8 d8 1d 1c 2b 1c 13 9b df e0 9e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DarkComet_ADK_2147894002_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DarkComet.ADK!MTB"
        threat_id = "2147894002"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkComet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b ee 33 eb 23 e9 33 ee 03 fd 03 c7 8b f8 c1 e7 0c c1 e8 14 0b f8 03 f9 8b c7 8b 7a 08 03 3d 98 17 49 00 8b eb 33 e9 23 e8 33 eb 03 fd 03 f7 8b fe c1 e7 11 c1 ee 0f 0b fe 03 f8 8b f7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DarkComet_ADK_2147894002_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DarkComet.ADK!MTB"
        threat_id = "2147894002"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkComet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {50 6a 00 68 00 04 00 00 8d 84 24 78 02 00 00 50 ff 74 24}  //weight: 2, accuracy: High
        $x_1_2 = "Hook procedure has been installed successfully" ascii //weight: 1
        $x_1_3 = "Keylogger is up and running" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DarkComet_ADK_2147894002_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DarkComet.ADK!MTB"
        threat_id = "2147894002"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkComet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 4d cc 8d 45 d0 ba 2c 4e 48 00 e8 ?? ?? ?? ?? 8b 45 d0 e8 ?? ?? ?? ?? eb 20 8d 45 c4}  //weight: 2, accuracy: Low
        $x_1_2 = "DDOSHTTPFLOOD" ascii //weight: 1
        $x_1_3 = "BTRESULTUDP Flood|UDP Flood task finished" ascii //weight: 1
        $x_1_4 = "BTRESULTSyn Flood|Syn task finished" ascii //weight: 1
        $x_1_5 = "BTRESULTHTTP Flood|Http Flood task finished" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DarkComet_ADC_2147897606_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DarkComet.ADC!MTB"
        threat_id = "2147897606"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkComet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {51 50 6a 00 0f 29 84 24 ?? ?? ?? ?? ff d7 6a 00 6a 00 6a 00 8d 84 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DarkComet_ADC_2147897606_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DarkComet.ADC!MTB"
        threat_id = "2147897606"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkComet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {50 8b 45 fc e8 39 4d f8 ff 50 a1 d8 87 4a 00 50}  //weight: 1, accuracy: High
        $x_1_2 = {6a 00 6a 00 6a 00 6a 00 68 e4 0b 48 00 e8 5c e8 fa ff}  //weight: 1, accuracy: High
        $x_1_3 = {8d 45 f8 50 6a 00 53 68 68 09 49 00 6a 00 6a 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DarkComet_ADR_2147899803_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DarkComet.ADR!MTB"
        threat_id = "2147899803"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkComet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {52 56 50 ff d3 85 c0 75 12 8d 4c 24 10 51 ff d5 8d 54 24 10 52 ff 15 20 f1 40 00 6a 00 6a 00 6a 00 8d 44 24 1c 50}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DarkComet_ND_2147910571_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DarkComet.ND!MTB"
        threat_id = "2147910571"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkComet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "strcpyAmpWriteFile" ascii //weight: 1
        $x_1_2 = "deCharToMultiByB" ascii //weight: 1
        $x_1_3 = "ViBalQuery" ascii //weight: 1
        $x_1_4 = "yPaForSHgXObjPt" ascii //weight: 1
        $x_1_5 = "UnhAdZjp" ascii //weight: 1
        $x_1_6 = "wpohKText" ascii //weight: 1
        $x_1_7 = "7JAtomA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DarkComet_ADE_2147912276_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DarkComet.ADE!MTB"
        threat_id = "2147912276"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkComet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 6a 00 53 68 2c 88 48 00 6a 00 6a 00 e8 ?? ?? ?? ?? db 6d e8 d8 25 ac 8a 48 00 db 7d e8 9b db 6d e8 d8 1d a4 8a 48 00 9b df e0 9e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DarkComet_AKM_2147912711_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DarkComet.AKM!MTB"
        threat_id = "2147912711"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkComet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {50 6a 00 53 68 d8 36 15 00 6a 00 6a 00 e8 8b 40 f8 ff db 6d e8 d8 25 b0 39 15 00 db 7d e8 9b db 6d e8 d8 1d a8 39 15 00 9b df e0 9e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DarkComet_MBXX_2147921643_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DarkComet.MBXX!MTB"
        threat_id = "2147921643"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkComet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {30 25 40 00 98 12 40 00 00 f0 30 00 00 ff ff ff 08 00 00 00 01 00 00 00 00 00 00 00 e9 00 00 00 28 11 40 00 28 11 40 00 ec 10 40 00 78 00 00 00 80}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DarkComet_MBXY_2147922177_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DarkComet.MBXY!MTB"
        threat_id = "2147922177"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkComet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {84 76 41 00 0e f9 30 00 00 ff ff ff 08 00 00 00 01}  //weight: 2, accuracy: High
        $x_1_2 = {e9 00 00 00 68 74 41 00 d4 73 41 00 68 3b 40 00 78 00 00 00 86 00 00 00 8e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DarkComet_ADO_2147942474_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DarkComet.ADO!MTB"
        threat_id = "2147942474"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkComet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 14 8b 55 08 03 c2 89 45 f8 8b 01 03 45 0c 8b ce 99 f7 f9 8b 45 f8 8a 8c 95 94 fb ff ff 30 08}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DarkComet_AKD_2147945772_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DarkComet.AKD!MTB"
        threat_id = "2147945772"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkComet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "dontuseme.ct8.pl" ascii //weight: 5
        $x_4_2 = "cmd /c sc delete IntelGpuUpdater && cmd /c sc stop IntelGpuUpdater" ascii //weight: 4
        $x_1_3 = "Unable to reach the server" ascii //weight: 1
        $x_2_4 = "Please restart your router or your PC to make sure it's connected to the internet" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DarkComet_AMDK_2147945899_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DarkComet.AMDK!MTB"
        threat_id = "2147945899"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkComet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8d 95 fc fb ff ff 52 8d 85 f4 fb ff ff 50 8d 4d fc 51 8d 95 f0 fb ff ff 52 68 00 04 00 00 8d 85 f0 f7 ff ff 50 68 e4 22 41 00 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DarkComet_ADT_2147948706_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DarkComet.ADT!MTB"
        threat_id = "2147948706"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkComet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {8b fe 33 d2 8b 4d 0c 85 c9 75 04 c9 c2 ?? ?? 83 fa 10 75 02 33 d2 ac 32 82 ?? ?? ?? ?? aa 42 49 75}  //weight: 3, accuracy: Low
        $x_2_2 = {57 8b 4d 0c 8b 7d 08 51 0f 31 33 c1 83 e0 0f 04 41 aa 59 49}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DarkComet_AMT_2147959236_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DarkComet.AMT!MTB"
        threat_id = "2147959236"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkComet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WARNING - MALWARE" ascii //weight: 1
        $x_1_2 = "This is considered Malware" ascii //weight: 1
        $x_1_3 = "If you run it, it can maybe break your PC" ascii //weight: 1
        $x_1_4 = "Are you sure you want to continue" ascii //weight: 1
        $x_1_5 = "FINAL WARNING - YOU CANT GO BACK" ascii //weight: 1
        $x_2_6 = "This Will Flash GDI, Play loud sounds and launch Payloads" ascii //weight: 2
        $x_1_7 = "Not For Epileptic" ascii //weight: 1
        $x_1_8 = "DONT RUN IF YOU DONT KNOW WHAT YOU'RE DOING" ascii //weight: 1
        $x_1_9 = "Press YES only if you know what you're doing, and is in a virtual Machine" ascii //weight: 1
        $x_1_10 = "mousemovah.exe" ascii //weight: 1
        $x_3_11 = "taskkill /f /im \"Decrypted File.exe\"" ascii //weight: 3
        $x_4_12 = "taskkill /f /im \"Blue Wave.exe\"" ascii //weight: 4
        $x_2_13 = "C++ Ransom.exe" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

