rule Trojan_Win32_BadJoke_PA_2147744904_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BadJoke.PA!MTB"
        threat_id = "2147744904"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BadJoke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "/C del %systemroot% /F /S /Q" ascii //weight: 5
        $x_5_2 = "ogo pososi huy" ascii //weight: 5
        $x_2_3 = "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v DisableTaskMgr /t REG_DWORD /d 1 /f" ascii //weight: 2
        $x_2_4 = "reg add HKCUSoftwareMicrosoftWindowsCurrentVersionPoliciesSystem /v DisableTaskMgr /t REG_DWORD /d 1 /f" ascii //weight: 2
        $x_2_5 = "test\\imlox\\imlox\\Release\\imlox.pdb" ascii //weight: 2
        $x_2_6 = "schtasks /create /tn \"WindowsUpdatev1\" /tr \"C:\\myapp.exe\" /sc onlogon" ascii //weight: 2
        $x_2_7 = "open \"C:\\TEMP\\some.mp3\" type mpegvideo alias errormsg" ascii //weight: 2
        $x_2_8 = "open \"C:\\TEMP\\some.mp3\" type mpegvideo alias justsnd" ascii //weight: 2
        $x_1_9 = "play errormsg repeat" ascii //weight: 1
        $x_1_10 = "play justsnd repeat" ascii //weight: 1
        $x_1_11 = "some.png" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 5 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_5_*) and 6 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_5_*) and 3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_5_*) and 4 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_BadJoke_PA_2147744904_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BadJoke.PA!MTB"
        threat_id = "2147744904"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BadJoke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "vssadmin delete shadows /all /quiet" ascii //weight: 1
        $x_1_2 = "Congratulations.txt" ascii //weight: 1
        $x_1_3 = "excuse me mate you installed malware on the system" ascii //weight: 1
        $x_1_4 = "Yeah Yeah its 420 time" wide //weight: 1
        $x_1_5 = "#MAKEMALWAREGREATAGAIN" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_BadJoke_AM_2147817632_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BadJoke.AM!MTB"
        threat_id = "2147817632"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BadJoke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SeShutdownPrivilege" ascii //weight: 1
        $x_1_2 = "DelNodeRunDLL32" ascii //weight: 1
        $x_1_3 = "POSTRUNPROGRAM" ascii //weight: 1
        $x_1_4 = "Lol get epicly reked/pwned by my epic VBScript!" ascii //weight: 1
        $x_1_5 = "I copied FlyTech's homework!" ascii //weight: 1
        $x_1_6 = "Get spamed" ascii //weight: 1
        $x_1_7 = "start box.vbs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BadJoke_RDA_2147845700_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BadJoke.RDA!MTB"
        threat_id = "2147845700"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BadJoke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {c1 e0 0d 33 c2 8b c8 c1 e9 11 33 c8 8b f9 c1 e7 05 33 f9 8b c7 c1 e0 0d 33 c7 8b c8 c1 e9 11 33 c8}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BadJoke_RDB_2147851744_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BadJoke.RDB!MTB"
        threat_id = "2147851744"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BadJoke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a 0a 8b 55 ec 8a 54 15 cf 31 ca 88 10}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BadJoke_GH_2147905025_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BadJoke.GH!MTB"
        threat_id = "2147905025"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BadJoke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DestructSafety.pdb" ascii //weight: 1
        $x_1_2 = "The software you just executed is considered malware." ascii //weight: 1
        $x_1_3 = "This malware will harm your computer and makes it unusable." ascii //weight: 1
        $x_1_4 = "If you are seeing this message without knowing what you just executed," ascii //weight: 1
        $x_1_5 = "press Yes to start it. Do you want to execute this malware, resulting in an unusable machine?" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BadJoke_EARZ_2147934439_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BadJoke.EARZ!MTB"
        threat_id = "2147934439"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BadJoke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8b c2 83 c2 02 d3 e8 32 c1 88 84 0d 78 56 fc ff 41 81 fa 38 53 07 00}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BadJoke_EARZ_2147934439_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BadJoke.EARZ!MTB"
        threat_id = "2147934439"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BadJoke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8b d0 8b c8 c1 e9 08 0a c8 c1 ea 09 0a d0 02 d1 8b c8 c1 e9 07 0a c8 02 d1 8b c8 c1 e9 06 22 c8 02 d1 88 94 05 f8 59 f1 ff 40 3d 00 a6 0e 00}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BadJoke_DAA_2147935401_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BadJoke.DAA!MTB"
        threat_id = "2147935401"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BadJoke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {89 c1 8b 45 fc c1 f8 0b 09 c8 21 d0 89 c2 89 d0 c1 e0 02 01 d0 8d 14 85 00 00 00 00 01 d0 c1 e0 02 89 c2 8b 45 fc 8d 0c 00 8b 45 10 01 c8 66 89 10 83 45 fc 01}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BadJoke_DAB_2147935402_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BadJoke.DAB!MTB"
        threat_id = "2147935402"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BadJoke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {89 c1 d3 eb 89 d8 83 e0 03 89 c1 d3 ea 89 d0 89 c1 8d 95 ?? ?? ?? ?? 8b 45 f4 01 d0 88 08 83 45 f4 01 81 7d f4}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BadJoke_EAOC_2147935739_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BadJoke.EAOC!MTB"
        threat_id = "2147935739"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BadJoke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8b d0 0f be c8 c1 ea 0e 8b d8 80 e2 0e c1 eb 05 0f be d2 0f af d1 8a c8 22 cb 02 c9 02 d1 2a d3 88 94 05 78 56 fc ff 40 3d 80 a9 03 00}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BadJoke_EAQL_2147935749_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BadJoke.EAQL!MTB"
        threat_id = "2147935749"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BadJoke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {d1 88 94 05 78 56 fc ff 40 3d 80 a9 03 00 72}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BadJoke_EAPX_2147936236_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BadJoke.EAPX!MTB"
        threat_id = "2147936236"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BadJoke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {88 8c 1d 78 56 fc ff 43 81 fb ?? ?? ?? ?? ?? ?? 8d 85 78 56 fc ff c7 85 44 56 fc ff 80 a9 03 00 89 85 40 56 fc ff 8d 85 40 56 fc ff}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BadJoke_EAMG_2147936238_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BadJoke.EAMG!MTB"
        threat_id = "2147936238"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BadJoke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {22 c2 88 84 0d 78 56 fc ff 41 81 f9 80 a9 03 00}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BadJoke_EALQ_2147936242_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BadJoke.EALQ!MTB"
        threat_id = "2147936242"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BadJoke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {88 9c 35 78 56 fc ff 46 81 fe 80 a9 03 00 ?? ?? 8d 85 78 56 fc ff c7 85 44 56 fc ff 80 a9 03 00 89 85 40 56 fc ff 8d 85 40 56 fc ff}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BadJoke_SPLS_2147936308_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BadJoke.SPLS!MTB"
        threat_id = "2147936308"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BadJoke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "x = msgbox(\"your pc is hacked!\", 0+48, \"ach\")" ascii //weight: 2
        $x_1_2 = "start https://yandex.ru/search/?text=you+are+hacked+by+ach+vzlom&clid=2411726&lr=43" ascii //weight: 1
        $x_1_3 = "x = msgbox(\"threat named trojan:win32:windows founded! you need delete windows!\", 0+48, \"windows defender\")" ascii //weight: 1
        $x_1_4 = "SELECT * FROM Win32_OperatingSystem" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BadJoke_EAGM_2147936730_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BadJoke.EAGM!MTB"
        threat_id = "2147936730"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BadJoke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {88 84 0d f8 f3 fa ff 41 81 f9 fe 0b 05 00 ?? ?? ?? ?? f8 f3 fa ff}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BadJoke_EASX_2147936731_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BadJoke.EASX!MTB"
        threat_id = "2147936731"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BadJoke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {88 94 05 f8 f3 fa ff 40 3d fe 0b 05 00 ?? ?? ?? ?? f8 f3 fa ff}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BadJoke_ABD_2147936996_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BadJoke.ABD!MTB"
        threat_id = "2147936996"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BadJoke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff d0 83 ec 04 c7 44 24 04 00 00 00 00 c7 04 24 02 ?? ?? ?? ?? ?? ?? ?? ?? 83 ec 08 89 45 f4 c7 44 24 08 2c 02 00 00 c7 44 24 04 00 00 00 00 8d 85 c8 fd ff ff 89 04 24 e8 ?? ?? ?? ?? c7 85 c8 fd ff ff 2c 02 00 00 8d 85 c8 fd ff ff 89 44 24 04 8b 45 f4 89 04 24 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BadJoke_EAOU_2147938599_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BadJoke.EAOU!MTB"
        threat_id = "2147938599"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BadJoke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8d 95 5e 56 fc ff 8b 45 f4 01 d0 88 08 83 45 f4 01 81 7d f4 80 a9 03 00}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BadJoke_EAZ_2147938603_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BadJoke.EAZ!MTB"
        threat_id = "2147938603"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BadJoke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {32 d0 2a d0 88 90 80 f8 42 00 40 3d 05 52 00 00 72}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BadJoke_EALB_2147940170_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BadJoke.EALB!MTB"
        threat_id = "2147940170"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BadJoke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {29 c2 8d 8d e2 59 f1 ff 8b 45 f4 01 c8 88 10 83 45 f4 01 81 7d f4 00 a6 0e 00}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BadJoke_PGB_2147942774_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BadJoke.PGB!MTB"
        threat_id = "2147942774"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BadJoke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b ca 8b c2 c1 e8 ?? c1 e9 ?? 32 c8 8b c2 c1 e8 ?? 0a c8 0f be c2 0f be c9 0f af c8 8a c1 02 c9 02 c1 c0 e0 ?? 88 84 15 ?? ?? ?? ?? 42 81 fa ?? ?? ?? ?? 72}  //weight: 5, accuracy: Low
        $x_5_2 = {8b ca 4d 8d 40 ?? c1 e9 ?? 8b c2 c1 e8 ?? 32 c8 8b c2 c1 e8 ?? 0a c8 0f be c2 0f be c9 ff c2 0f af c8 0f b6 c1 02 c0 02 c8 c0 e1 ?? 41 88 48 ?? 81 fa ?? ?? ?? ?? 72}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

