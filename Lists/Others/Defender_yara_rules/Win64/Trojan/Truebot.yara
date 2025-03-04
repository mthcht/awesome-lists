rule Trojan_Win64_Truebot_B_2147844396_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Truebot.B"
        threat_id = "2147844396"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Truebot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "ChkdskExs" ascii //weight: 1
        $x_1_2 = "%s\\%s.JSONIP" ascii //weight: 1
        $x_1_3 = "process call create \"powershell -executionpolicy bypass -nop -w hidden" ascii //weight: 1
        $x_1_4 = "%s\\%08x-%08x.ps1" ascii //weight: 1
        $x_1_5 = "ldr_sys64.dll" ascii //weight: 1
        $x_1_6 = {2e 00 6d 00 70 00 34 00 [0-8] 53 65 44 65 62 75 67 50 72 69 76 69 6c 65 67 65}  //weight: 1, accuracy: Low
        $x_1_7 = {53 45 41 52 43 48 41 50 50 [0-10] 43 54 46 4d 4f 4e}  //weight: 1, accuracy: Low
        $x_1_8 = {55 4e 4b 57 [0-10] 32 30 30 [0-10] 58 50}  //weight: 1, accuracy: Low
        $x_1_9 = "n=%s&o=%s&a=%d&u=%s&p=%s&d=%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Trojan_Win64_Truebot_ZG_2147898779_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Truebot.ZG!MTB"
        threat_id = "2147898779"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Truebot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\Users\\user\\Documents\\Project\\check_name\\target\\release\\deps\\FingerPrint_disable.pdb" ascii //weight: 1
        $x_1_2 = "QtWebEngineProcess.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

