rule Trojan_Win32_DarkGate_RPX_2147890447_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DarkGate.RPX!MTB"
        threat_id = "2147890447"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkGate"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 8d c4 f9 ff ff 83 c4 1c ff 71 1c ff 95 ac f9 ff ff 8b 85 c4 f9 ff ff 53 8b 9d b0 f9 ff ff 8b 40 10 83 c0 38 50 ff d3 8b 85 c4 f9 ff ff ff b5 b4 f9 ff ff 8b 40 10 83 c0 40 50 ff d3 68 04 01 00 00 8d 85 e0 f9 ff ff 50 6a 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DarkGate_EB_2147891227_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DarkGate.EB!MTB"
        threat_id = "2147891227"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkGate"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "178.236.247.102:9999" ascii //weight: 1
        $x_1_2 = "lsass.exe|kav.exe|avpcc.exe|_avpm.exe|avp32.exe|avp.exe|antivirus.exe|" ascii //weight: 1
        $x_1_3 = "--mute-audio --disable-audio --no-sandbox --new-window --disable-3d-apis" ascii //weight: 1
        $x_1_4 = "--disable-gpu --disable-d3d11 --window-size=" ascii //weight: 1
        $x_1_5 = "RSActionSendHQScreenshot" ascii //weight: 1
        $x_1_6 = "darkgate.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DarkGate_A_2147891845_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DarkGate.A!MTB"
        threat_id = "2147891845"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkGate"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 04 24 0f b6 44 18 ?? 33 f8 43 4e}  //weight: 2, accuracy: Low
        $x_2_2 = {8b d7 32 54 1d ?? f6 d2 88 54}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DarkGate_ZZ_2147892209_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DarkGate.ZZ"
        threat_id = "2147892209"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkGate"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "241"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f1 d5 00 fa 4c 62 cc f4 0f 0b}  //weight: 1, accuracy: High
        $x_100_2 = {80 e1 3f c1 e1 02 8a 5d ?? 80 e3 30 81 e3 ff 00 00 00 c1 eb 04 02 cb}  //weight: 100, accuracy: Low
        $x_100_3 = {80 e1 0f c1 e1 04 8a 5d ?? 80 e3 3c 81 e3 ff 00 00 00 c1 eb 02 02 cb}  //weight: 100, accuracy: Low
        $x_10_4 = "____padoru____" ascii //weight: 10
        $x_10_5 = "Error: no delimitador monitor" ascii //weight: 10
        $x_10_6 = "hvnc error" ascii //weight: 10
        $x_10_7 = "-accepteula -d -u " ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DarkGate_B_2147892791_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DarkGate.B!MTB"
        threat_id = "2147892791"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkGate"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 14 24 8a 54 32 ff 8a 4c 1d ff 32 d1 88 54 30 ff 8b c5}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DarkGate_C_2147892792_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DarkGate.C!MTB"
        threat_id = "2147892792"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkGate"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {32 c2 f6 d0 5a 88 02 ff 06 4b}  //weight: 2, accuracy: High
        $x_2_2 = {8b 06 0f b6 44 05 ?? 31 05 ?? ?? ?? ?? ff 06 4b}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DarkGate_AD_2147892903_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DarkGate.AD!MTB"
        threat_id = "2147892903"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkGate"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "101"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f1 d5 00 fa 4c 62 cc f4 0f 0b}  //weight: 1, accuracy: High
        $x_100_2 = {8b 44 24 04 [0-16] 8b d7 32 54 1d ff f6 d2 88 54 18 ff 43 4e [0-48] 8b 44 24 04}  //weight: 100, accuracy: Low
        $x_100_3 = {8b 44 24 04 [0-16] 8b 14 24 8a 54 32 ff 8a 4c 1d ff 32 d1 88 54 30 ff 8b c5 [0-16] 3b d8 7d 03 43 eb 05 bb 01 00 00 00 46 4f 8b 44 24 04}  //weight: 100, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 1 of ($x_1_*))) or
            ((2 of ($x_100_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_DarkGate_MB_2147893048_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DarkGate.MB!MTB"
        threat_id = "2147893048"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkGate"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8d 44 10 ff 50 a1 ?? ?? ?? ?? 8a 44 07 ff 8b 15 ?? ?? ?? ?? 8a 54 16 ff 32 c2 5a 88 02 8b c6 e8 ?? ?? ?? ?? 3b 05 ?? ?? ?? ?? 7e 08 ff 05 ?? ?? ?? ?? eb 0a c7 05 ?? ?? ?? ?? 01 00 00 00 ff 05 ?? ?? ?? ?? 4b 75}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DarkGate_AL_2147893106_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DarkGate.AL!MTB"
        threat_id = "2147893106"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkGate"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 42 04 b8 ?? ?? ?? ?? 8b 4a ?? 2b 44 24 ?? 01 82 ?? ?? 00 00 8b 47 ?? 0f af ce 89 af ?? ?? 00 00 89 4c 24 ?? 8b d1 8b 4f ?? 8b 5c 24 ?? c1 ea}  //weight: 1, accuracy: Low
        $x_1_2 = {88 14 01 8b cb ff 47 ?? 8b 57 ?? 8b 47 ?? c1 e9 ?? 88 0c 02 ff 47 ?? 8b 4f ?? 8b 47 ?? 88 1c 01 8b 4c 24 ?? ff 47 ?? 83 c1 04 89 4c 24 ?? 81 f9 ?? ?? ?? ?? 0f 8c ?? ?? ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DarkGate_SE_2147894359_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DarkGate.SE!MTB"
        threat_id = "2147894359"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkGate"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "zLAxuU0kQKf3sWE7ePRO2imyg9GSpVoYC6rhlX48ZHnvjJDBNFtMd1I5acwbqT" ascii //weight: 2
        $x_2_2 = "\\data.bin" ascii //weight: 2
        $x_2_3 = "SideLoader.dll" ascii //weight: 2
        $x_1_4 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 1
        $x_1_5 = "System\\CurrentControlSet\\Control\\Keyboard Layouts" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DarkGate_CCDC_2147894402_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DarkGate.CCDC!MTB"
        threat_id = "2147894402"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkGate"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "zLAxuU0kQKf3sWE7ePRO2imyg9GSpVoYC6rhlX48ZHnvjJDBNFtMd1I5acwbqT+=" ascii //weight: 1
        $x_1_2 = "\\data.bin" ascii //weight: 1
        $x_1_3 = "JumpID(\"\",\"%s\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DarkGate_MD_2147894536_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DarkGate.MD!MTB"
        threat_id = "2147894536"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkGate"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "--HEIL HITLER--" ascii //weight: 1
        $x_1_2 = "darkloader" ascii //weight: 1
        $x_1_3 = "tp://darkloader.top/" wide //weight: 1
        $x_1_4 = "tp://closehub.ru/" wide //weight: 1
        $x_1_5 = "AntiStealerByDarkP1xel" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DarkGate_AC_2147895135_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DarkGate.AC!MTB"
        threat_id = "2147895135"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkGate"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b c7 f7 74 24 ?? 2b d1 8a 44 14 ?? 32 87 ?? ?? ?? ?? 88 04 3e 47}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DarkGate_AC_2147895135_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DarkGate.AC!MTB"
        threat_id = "2147895135"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkGate"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell.exe" wide //weight: 1
        $x_1_2 = "Invoke-WebRequest" wide //weight: 1
        $x_1_3 = "curl" wide //weight: 1
        $x_1_4 = "Autoit3.exe" wide //weight: 1
        $x_1_5 = "http://" wide //weight: 1
        $x_1_6 = ".au3" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DarkGate_ZY_2147901964_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DarkGate.ZY"
        threat_id = "2147901964"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkGate"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "241"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f1 d5 00 fa 4c 62 cc f4 0f 0b}  //weight: 1, accuracy: High
        $x_100_2 = {80 e1 3f c1 e1 02 8a 5d ?? 80 e3 30 81 e3 ff 00 00 00 c1 eb 04 02 cb}  //weight: 100, accuracy: Low
        $x_100_3 = {80 e1 0f c1 e1 04 8a 5d ?? 80 e3 3c 81 e3 ff 00 00 00 c1 eb 02 02 cb}  //weight: 100, accuracy: Low
        $x_10_4 = "meimportaunamierdasidescifrasloslogs" ascii //weight: 10
        $x_10_5 = "puerto is not number" ascii //weight: 10
        $x_10_6 = "delikey not found" ascii //weight: 10
        $x_10_7 = "--_Binder_--" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DarkGate_EM_2147903536_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DarkGate.EM!MTB"
        threat_id = "2147903536"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkGate"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "c:\\tmpp\\Autoit3.exe c:\\tmpp\\test.au3" ascii //weight: 1
        $x_1_2 = "c:\\debugg" ascii //weight: 1
        $x_1_3 = "noresdata" ascii //weight: 1
        $x_1_4 = "debugx2" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DarkGate_D_2147912988_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DarkGate.D!MTB"
        threat_id = "2147912988"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkGate"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f b7 c0 99 f7 fd 83 6c ?? ?? ?? 8b c2 99 f7 ff 8b 7c ?? ?? 31 01 8b 44}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DarkGate_MKV_2147914413_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DarkGate.MKV!MTB"
        threat_id = "2147914413"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkGate"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b cf f7 e7 8b c7 2b c2 d1 e8 03 c2 c1 e8 04 6b c0 13 2b c8 2b ce 8a 44 0c 24 32 87 ?? ?? ?? ?? 88 04 2f 47 81 ff 00 ca 16 00 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DarkGate_MVV_2147914450_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DarkGate.MVV!MTB"
        threat_id = "2147914450"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkGate"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 14 07 83 c7 04 8b 86 e8 00 00 00 35 36 67 03 00 29 41 08 8b 9e 80 00 00 00 a1 ?? ?? ?? ?? 0f af da 8b 88 ac 00 00 00 8b 86 ?? ?? ?? ?? 8b d3 c1 ea 10 88 14 01 8b d3 ff 86 ?? ?? ?? ?? 8b 86 c8 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DarkGate_MGV_2147914552_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DarkGate.MGV!MTB"
        threat_id = "2147914552"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkGate"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c8 69 c1 cb 1d 00 00 b9 ff ff 00 00 2b 44 24 2c 99 f7 fe 8b 54 24 50 66 89 04 7a 8b 44 24 ?? 66 01 08 66 8b 00 0f b7 c8 0f b7 44 7a 0c 8b 54 24 18 3b 04 ca 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DarkGate_MZA_2147914632_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DarkGate.MZA!MTB"
        threat_id = "2147914632"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkGate"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b ce f7 e7 8b c7 2b c2 d1 e8 03 c2 c1 e8 04 03 c0 2b c8 8d 04 cd ?? ?? ?? ?? 2b c1 8d 04 47 8a 44 04 24 32 87 3c 21 6e 00 88 04 2f 47 81 ff 00 d2 16 00 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DarkGate_WRY_2147914761_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DarkGate.WRY!MTB"
        threat_id = "2147914761"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkGate"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 48 64 8b 86 88 00 00 00 88 1c 01 a1 ?? ?? ?? ?? ff 40 64 ?? ?? ?? ?? 00 8b 8e d8 00 00 00 2b 88 ac 00 00 00 8b 86 e0 00 00 00 83 f1 f7 2b 86 ?? ?? ?? ?? 01 8e 18 01 00 00 05 6b 62 20 00 0f af 86 84 00 00 00 89 86 84 00 00 00 a1 ?? ?? ?? ?? 48 31 46 14 81 fd e8 d3 01 00 0f 8c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DarkGate_MVW_2147914854_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DarkGate.MVW!MTB"
        threat_id = "2147914854"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkGate"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 06 8b 4e 34 2d 4f 38 12 00 0f af 46 54 89 46 54 a1 ?? ?? ?? ?? 88 1c 08 ff 46 34 8b 0d ?? ?? ?? ?? 8b 41 54 2d bc a0 11 00 31 81 80 00 00 00 81 ff e8 14 00 00 0f 8c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DarkGate_MKD_2147915235_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DarkGate.MKD!MTB"
        threat_id = "2147915235"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkGate"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6b c8 0c 83 44 24 14 04 83 44 24 18 08 8b 04 83 0f af 83 e0 0a 00 00 31 81 e8 19 00 00 0f b6 05 ?? ?? ?? ?? 0f b6 4c 37 05 05 98 15 00 00 f7 f1 8b 4c 24 24 88 54 37 05 46 a1 ?? ?? ?? ?? 89 74 24 10 0f b6 04 08 3b f0 0f 84}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DarkGate_MKF_2147915236_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DarkGate.MKF!MTB"
        threat_id = "2147915236"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkGate"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {99 f7 f9 8b 4c 24 20 66 a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? ff 44 24 3c 0f b7 0c 41 0f b7 04 5f 2b c8 8b 44 24 38 31 88 30 78 00 00 8b 44 24 10 0f b7 35 ?? ?? ?? ?? 0f b7 08 a1 ?? ?? ?? ?? 3b 34 88 7d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DarkGate_DGZ_2147915610_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DarkGate.DGZ!MTB"
        threat_id = "2147915610"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkGate"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 e6 8b c6 8b cd 2b c2 d1 e8 03 c2 c1 e8 04 6b c0 1b 2b c8 03 ce 8a 44 0c 20 32 86 ?? ?? ?? ?? 46 88 47 ff 81 fe 00 d4 16 00 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DarkGate_BAN_2147916323_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DarkGate.BAN!MTB"
        threat_id = "2147916323"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkGate"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 d2 f7 75 fc 43 8a 04 32 8b 55 f8 32 04 0a 8b 55 f4 88 01 3b 5d 08 72 d8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DarkGate_BAY_2147916367_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DarkGate.BAY!MTB"
        threat_id = "2147916367"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkGate"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b ce f7 e7 8b c7 2b c2 d1 e8 03 c2 c1 e8 04 6b c0 13 2b c8 03 cf 8a 44 0c 24 32 87 3c 21 6e 00 88 04 2f 47 81 ff 00 06 33 00 72 cf}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DarkGate_JZE_2147917943_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DarkGate.JZE!MTB"
        threat_id = "2147917943"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkGate"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 0c 02 a1 ?? ?? ?? ?? 33 48 38 8b 80 88 00 00 00 89 0c 02 83 c2 04 a1 ?? ?? ?? ?? 8b 8f a4 00 00 00 2b 48 50 41 0f af 4f 1c 89 4f 1c a1 ?? ?? ?? ?? 01 47 38 81 fa dc 96 17 00 0f 8c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DarkGate_NEQ_2147918309_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DarkGate.NEQ!MTB"
        threat_id = "2147918309"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkGate"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {42 33 c0 8b ce 2a c8 32 0c 07 8b 5d fc 8b 1b 88 0c 03 40 4a 75 ed}  //weight: 5, accuracy: High
        $x_3_2 = {8b 55 f4 8a 14 32 8b 4d f8 32 14 19 88 14 30 8b 45 f8 e8 ?? ?? ?? ?? 50 8b 45 f8 0f b6 04 18}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DarkGate_ZX_2147920513_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DarkGate.ZX"
        threat_id = "2147920513"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkGate"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "221"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f1 d5 00 fa 4c 62 cc f4 0f 0b}  //weight: 1, accuracy: High
        $x_100_2 = {80 e1 3f c1 e1 02 8a 5d ?? 80 e3 30 81 e3 ff 00 00 00 c1 eb 04 02 cb}  //weight: 100, accuracy: Low
        $x_100_3 = {80 e1 0f c1 e1 04 8a 5d ?? 80 e3 3c 81 e3 ff 00 00 00 c1 eb 02 02 cb}  //weight: 100, accuracy: Low
        $x_10_4 = "--_Binder_--" ascii //weight: 10
        $x_10_5 = "||_Binder_||" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DarkGate_BKC_2147923085_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DarkGate.BKC!MTB"
        threat_id = "2147923085"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkGate"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {99 f7 f9 8b 44 24 04 8a 04 10 8b 14 24 8b 0d a0 f8 5e 00 8a 54 0a ff 32 c2 50 8b 44 24 0c e8 32 e8 f8 ff 8b 15 a0 f8 5e 00 59 88 4c 10 ff}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DarkGate_MRT_2147923550_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DarkGate.MRT!MTB"
        threat_id = "2147923550"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkGate"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {83 c4 08 8b 55 e4 8b 4d dc 8b 45 d8 03 ca 42 89 55 ?? 8a 04 08 32 45 ef 88 01 3b 55 08 0f 82}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DarkGate_MRM_2147923551_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DarkGate.MRM!MTB"
        threat_id = "2147923551"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkGate"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {33 d2 8b c6 6a ?? 59 f7 f1 8b 44 24 18 8a 4c 14 1c 32 8e ?? ?? ?? ?? 88 0c 06 46 3b 74 24 ?? 72}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DarkGate_GGF_2147925632_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DarkGate.GGF!MTB"
        threat_id = "2147925632"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkGate"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b c1 f7 75 e4 8b 45 ?? 8a 14 32 32 14 01 8b c7 83 7f 14 0f 76 ?? 8b 07 88 14 08 41 8b 45 d4 83 f9 27 72}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DarkGate_MUV_2147926628_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DarkGate.MUV!MTB"
        threat_id = "2147926628"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkGate"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b c1 f7 75 e4 8b 45 d0 8a 14 32 32 ?? 01 8b c7 83 7f 14 0f 76 ?? 8b 07 88 14 08 41 8b 45 d4 83 f9 ?? 72}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DarkGate_SIP_2147927535_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DarkGate.SIP!MTB"
        threat_id = "2147927535"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkGate"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 68 95 83 40 00 64 ff 30 64 89 20 83 7d fc 00 74 25 8b 45 f8 e8 cf b8 ff ff 50 8d 45 f8 e8 72 ba ff ff 8b d0 8b 45 fc 59}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DarkGate_GC_2147928155_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DarkGate.GC!MTB"
        threat_id = "2147928155"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkGate"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {31 d2 f7 f3 8a 04 16 30 04 0f}  //weight: 1, accuracy: High
        $x_1_2 = {41 89 c8 81 f9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DarkGate_GC_2147928155_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DarkGate.GC!MTB"
        threat_id = "2147928155"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkGate"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a c7 f7 a4 9e e9 00 00 00 00 e8 69 07 00 00 0b 6c 63 6c 48 d7 57 ad d2 84 3c 15 62 30 cb 30 f3 30 98 64 84 64 10 64 f1 64 71 29}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DarkGate_GB_2147928416_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DarkGate.GB!MTB"
        threat_id = "2147928416"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkGate"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 d2 f7 f3}  //weight: 1, accuracy: High
        $x_1_2 = {30 04 0f 41 89 c8 81 f9 [0-4] 76}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DarkGate_TKV_2147928653_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DarkGate.TKV!MTB"
        threat_id = "2147928653"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkGate"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {f7 f3 8a 04 16 60 f2 0f 5c d4 f2 0f 10 e6 f2 0f 5c fa f2 0f 5c d4 f2 0f 2d c3 66 0f 59 d9 66 0f 14 c0 61 30 04 0f 41 89 c8 81 f9 07 80 17 00 76 cd}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DarkGate_ND_2147928804_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DarkGate.ND!MTB"
        threat_id = "2147928804"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkGate"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {33 c0 c7 84 24 30 01 00 00 00 00 00 00 c7 84 24 34 01 00 00 07 00 00 00 66 89 84 24 20 01 00 00 83 f9 07 76 36 8b 94 24 90 00 00 00 8d 0c 4d 02 00 00 00 8b c2 81 f9 00 10 00 00 72 14 8b 50 fc 83 c1 23 2b c2}  //weight: 3, accuracy: High
        $x_1_2 = "34WKSI.aiff" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DarkGate_SHC_2147929246_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DarkGate.SHC!MTB"
        threat_id = "2147929246"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkGate"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {64 a1 30 00 00 00 60 89 f9 0f 95 c0 89 f9 85 ff 0f 44 c1 81 e7 ff ff fd ff bb 01 00 00 00 83 e1 08 09 c8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DarkGate_NNJ_2147929248_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DarkGate.NNJ!MTB"
        threat_id = "2147929248"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkGate"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8d 0c 07 33 d2 8b c7 f7 75 ?? 47 8a 04 32 8b 55 ?? 32 04 11 88 01 8b 45 b0 8b 8d ?? ?? ff ff 3b 7d ac 72}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DarkGate_DA_2147932155_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DarkGate.DA!MTB"
        threat_id = "2147932155"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkGate"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd.exe" wide //weight: 1
        $x_10_2 = "/c wmic ComputerSystem get domain" wide //weight: 10
        $x_1_3 = "> C:\\" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DarkGate_KKK_2147933438_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DarkGate.KKK!MTB"
        threat_id = "2147933438"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkGate"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {f7 f3 c5 ed fd d6 c5 e5 fd df c5 ed 67 d2 c5 e5 67 db 8a 04 16 c5 d5 fd ef c5 dd 67 e4 c5 d5 67 ed c5 fd 60 c2 30 04 0f c5 fd 69 f4 c5 fd 61 c4 c5 dd 73 dc 02 c5 f5 73 db ?? c5 e5 69 d7 41 c5 e5 6a dc c5 f5 ef c9 c5 e5 75 db c5 e5 71 f3 07 c4 e3 fd 00 f6 ?? 89 c8 c5 cd 60 e1 c5 cd 68 f1 c5 c5 60 c1 c5 c5 68 f9 81 f9 07 80 17 00 0f 86}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DarkGate_KKM_2147933439_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DarkGate.KKM!MTB"
        threat_id = "2147933439"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkGate"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {31 d2 c5 e5 60 dd c5 c5 73 d8 02 c5 fd 69 f4 c5 fd 61 c4 f7 f3 c5 fd 62 c3 c5 e5 6a dc 8a 04 16 c5 e5 67 db c5 dd fd e6 c5 d5 fd ef 30 04 0f c5 e5 60 dd 41 c5 c5 73 d8 ?? 89 c8 81 f9 07 74 17 00 76}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DarkGate_ZT_2147934389_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DarkGate.ZT"
        threat_id = "2147934389"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkGate"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "201"
        strings_accuracy = "Low"
    strings:
        $x_200_1 = {61 00 75 00 74 00 6f 00 69 00 74 00 33 00 2e 00 65 00 78 00 65 00 20 00 ?? ?? 3a 00 5c 00 70 00 72 00 6f 00 67 00 72 00 61 00 6d 00 64 00 61 00 74 00 61 00 5c 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 5c 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 00}  //weight: 200, accuracy: Low
        $x_1_2 = ".au3" wide //weight: 1
        $x_1_3 = ".a3x" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_200_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_DarkGate_GD_2147934997_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DarkGate.GD!MTB"
        threat_id = "2147934997"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkGate"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {30 04 0f 41 89 c8 81 f9 07 7c 17 00 [0-30] 31 d2 [0-30] f7 f3 [0-30] 8a 04 16 [0-15] 83 c0 88}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DarkGate_GE_2147935570_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DarkGate.GE!MTB"
        threat_id = "2147935570"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkGate"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 f9 07 e4 06 00 [0-50] 31 d2 [0-60] f7 f3 [0-60] 8a 04 16 [0-60] 30 04 0f [0-60] 41 [0-60] 89 c8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

