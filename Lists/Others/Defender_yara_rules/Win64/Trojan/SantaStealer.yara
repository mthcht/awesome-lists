rule Trojan_Win64_SantaStealer_LM_2147959245_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/SantaStealer.LM!MTB"
        threat_id = "2147959245"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "SantaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "45"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {0f b6 14 03 83 f2 01 88 14 01 48 83 c0 01 4c 39 c0 75 ?? 4d 63 c9 48 89 c8 42 c6 04 09 00 48 83 c4 20}  //weight: 20, accuracy: Low
        $x_15_2 = "t.me/SantaStealer" ascii //weight: 15
        $x_5_3 = "ChromeElevator_GetEncryptedBlob" ascii //weight: 5
        $x_3_4 = "ChromeElevator_Cleanup" ascii //weight: 3
        $x_2_5 = "cryptocurrency" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_SantaStealer_A_2147959612_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/SantaStealer.A!AMTB"
        threat_id = "2147959612"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "SantaStealer"
        severity = "Critical"
        info = "AMTB: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Stealer" ascii //weight: 2
        $x_2_2 = "31.57.38.244" ascii //weight: 2
        $x_2_3 = "80.76.49.114" ascii //weight: 2
        $x_1_4 = "BrowserSummary.txt" ascii //weight: 1
        $x_1_5 = "Download History" ascii //weight: 1
        $x_1_6 = "config\\loginusers" ascii //weight: 1
        $x_1_7 = "Chrome|User Data" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_SantaStealer_PS_2147960283_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/SantaStealer.PS!MTB"
        threat_id = "2147960283"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "SantaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 0f b6 54 05 00 41 30 14 06 48 83 c0 01 48 3b 45 28 72 ec}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_SantaStealer_ABSS_2147961962_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/SantaStealer.ABSS!MTB"
        threat_id = "2147961962"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "SantaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {33 ca 45 33 c1 41 89 4c 9b ?? 48 8d 53 06 41 8b c0 24 ?? f6 d8 1b c9 81 e1 ?? ?? ?? ?? 41 33 8c 9b ?? ?? ?? ?? 48 8b da 41 d1 e8 41 33 c8 41 89 0c 93 48 81 fa}  //weight: 3, accuracy: Low
        $x_2_2 = "powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -Command " ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_SantaStealer_NH_2147962206_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/SantaStealer.NH!MTB"
        threat_id = "2147962206"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "SantaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 54 24 0c c1 e0 0d 31 d0 89 44 24 0c 8b 44 24 0c 8b 54 24 0c c1 e8 11 31 d0 89 44 24 0c 8b 44 24 0c 8b 54 24 0c c1 e0 05 31 d0 89 44 24 0c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_SantaStealer_BYD_2147963474_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/SantaStealer.BYD!MTB"
        threat_id = "2147963474"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "SantaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 4c 05 fd 30 4c 06 fd 0f b6 4c 05 fe 30 4c 06 fe 0f b6 4c 05 ff 30 4c 06 ff 0f b6 4c 05 00 30 0c 06 48 83 c0 04 48 83 f8 43 75 d3 eb 9f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

