rule Trojan_Win32_AgentCrypt_SN_2147771745_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AgentCrypt.SN!MTB"
        threat_id = "2147771745"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AgentCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GET ///RguhsT/accept.php?a=" ascii //weight: 1
        $x_1_2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_3 = "MPGoodStatus" ascii //weight: 1
        $x_1_4 = "local.foo.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AgentCrypt_SN_2147771745_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AgentCrypt.SN!MTB"
        threat_id = "2147771745"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AgentCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8d 1c 3b 8b 1b 81 e3 ff 00 00 00 29 c9 47 42 49 81 ff ?? ?? 00 00 75 05 bf 00 00 00 00 81 c2 ?? ?? ?? ?? c3}  //weight: 2, accuracy: Low
        $x_2_2 = {09 d2 31 1e 46 21 d2 39 c6 75 ?? c3}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AgentCrypt_SM_2147773023_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AgentCrypt.SM!MTB"
        threat_id = "2147773023"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AgentCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {55 89 e5 8d 64 24 ?? 50 e8 00 00 00 00 58 83 c0 ?? 89 45 ?? 58 8d 45 ?? e8 ?? ?? ?? ?? 8b 45 ?? 8b 00 89 45 ?? 8b 45 ?? 8b 40 ?? 89 45}  //weight: 2, accuracy: Low
        $x_2_2 = {6a 40 68 00 30 00 00 ff 75 ?? 6a 00 ff 55 ?? 89 45 ?? ff 75 ?? 8b 4d ?? 8b 55 ?? 8b 45 ?? e8 ?? ff ff ff 8d 55 ?? 8b 45 ?? e8 ?? ?? ?? ?? c9 c3}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AgentCrypt_SW_2147775313_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AgentCrypt.SW!MTB"
        threat_id = "2147775313"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AgentCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "array(\"HKCU\",\"HKLM\",\"HKCU\\vw0rm\",\"\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\\"," wide //weight: 2
        $x_2_2 = "array(\"winmgmts:\",\"win32_logicaldisk\",\"Win32_OperatingSystem\",\"winmgmts:\\\\localhost\\root\\securitycenter\",\"AntiVirusProduct\")" wide //weight: 2
        $x_2_3 = "Open \"POST\",\"http://127.0.0.1:5/\"&C,false" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AgentCrypt_SW_2147775313_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AgentCrypt.SW!MTB"
        threat_id = "2147775313"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AgentCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6a 40 68 00 30 00 00 68 ?? ?? ?? ?? 6a 00 ff 15 ?? ?? ?? ?? 89 45 ?? c7 85 ?? ?? ?? ?? 00 00 00 00 c7 45 ?? 00 00 00 00 eb}  //weight: 2, accuracy: Low
        $x_2_2 = {33 d1 8b 45 ?? 03 45 ?? 88 10 eb 50 00 99 f7 bd ?? ?? ?? ?? 89 95 ?? ?? ?? ?? 8b 4d ?? 03 4d ?? 0f be 11 8b 85 ?? ?? ?? ?? 0f be 4c 05}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

